// Package token : The Token package: Enables the transfer of users' information between clients and servers using secure JSON Web Token (JWT) cookies
package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	am "github.com/ibm-security-innovation/libsecurity-go/accounts"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
)

const (
	securityStr             = "Trusteer"
	tokenClaimsExpireStr    = "exp"
	tokenClaimsIssuerStr    = "iss"
	tokenClaimsAudienceStr  = "aud"
	tokenClaimsPrivilegeStr = "Privilege"
	tokenClaimsUpdatePasswordOnlyStr = "UpdatePass"
	tokenClaimsJtiStr       = "jti"
	tokenClaimsIPAddr       = "IPAddr"

	jwtLen = 128

	defaultTokenTimeExpirationMinutes = 30
)

var (
	jwtUniqID string

	usersList                                *en.EntityManager
	adminsGroup, superusersGroup, usersGroup *en.Entity
)

// SecureTokenData : The token information: token string, user name and privilege and ID
type SecureTokenData struct {
	Token     *jwt.Token
	UserName  string
	Privilege string
	UpdatePassword bool
	ID        string
}

func init() {
	jwtUniqID = generateJwt(jwtLen)

	usersList = en.New()

	usersList.AddGroup(defs.SuperUserGroupName)
	usersList.AddGroup(defs.AdminGroupName)
	usersList.AddGroup(defs.UsersGroupName)

	usersList.AddUserToGroup(defs.AdminGroupName, defs.SuperUserGroupName)
	usersList.AddUserToGroup(defs.UsersGroupName, defs.SuperUserGroupName)
	usersList.AddUserToGroup(defs.UsersGroupName, defs.AdminGroupName)
	usersList.AddUserToGroup(defs.SuperUserGroupName, defs.RootUserName)
}

func generateJwt(length int) string {
	val := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, val)
	if err != nil {
		logger.Error.Panic(fmt.Errorf("Random read failed: %v", err))
	}
	for i, c := range val {
		val[i] = c%74 + 48 // printable chars
	}
	return string(val)
}

// Return the RSA private key from the given file
func getPrivateKey(privateKeyFilePath string) (*rsa.PrivateKey, error) {
	signKey, err := ioutil.ReadFile(privateKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("Reading private key file: '%v'", privateKeyFilePath)
	}

	block, _ := pem.Decode(signKey)
	if block == nil {
		return nil, fmt.Errorf("Found while decoding the private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// SetupAToken : Read the given private key PEM file and extract an RSA private key (signing
// key) the corresponding RSA public key (verifying key)
func SetupAToken(privateKeyFilePath string) (*rsa.PrivateKey, *rsa.PublicKey) {
	var err error
	pKey, err := getPrivateKey(privateKeyFilePath)
	if err != nil {
		logger.Error.Fatal("reading private key file:", privateKeyFilePath)
	}
	return pKey, &pKey.PublicKey
}

// GenerateToken : Generate a new signed token
func GenerateToken(name string, privilege string, updatePasswordOnly bool, ipAddr string, signKey *rsa.PrivateKey) (string, error) {
	// create a signer for rsa 256
	token := jwt.New(jwt.SigningMethodRS256)

	token.Claims[tokenClaimsExpireStr] = time.Now().Add(time.Minute * defaultTokenTimeExpirationMinutes).Unix()
	token.Claims[tokenClaimsIssuerStr] = securityStr
	token.Claims[tokenClaimsAudienceStr] = name
	token.Claims[tokenClaimsJtiStr] = jwtUniqID
	token.Claims[tokenClaimsPrivilegeStr] = privilege
	token.Claims[tokenClaimsUpdatePasswordOnlyStr] = updatePasswordOnly
	token.Claims[tokenClaimsIPAddr] = ipAddr
	return token.SignedString(signKey)
}

// ParseToken : Parse the given token and verify that it holds the mandatory data
func ParseToken(tokenString string, ipAddr string, verifyKey *rsa.PublicKey) (*SecureTokenData, error) {
	token, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if token.Claims[tokenClaimsIssuerStr] != securityStr {
				return nil, fmt.Errorf("Token is not valid: It was not issued by trusteer")
			}
			if token.Claims[tokenClaimsJtiStr] != jwtUniqID {
				return nil, fmt.Errorf("oken is not valid: Wrong ID")
			}
			if token.Claims[tokenClaimsIPAddr] != ipAddr {
				return nil, fmt.Errorf("IP address (%v) does not match the IP address in the token (%v)", ipAddr, token.Claims[tokenClaimsIPAddr])
			}
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return verifyKey, nil
		})

	switch err.(type) {
	case nil: // no error
		if !token.Valid { // but may still be invalid
			return nil, fmt.Errorf("Token is not valid")
		}
		userName := token.Claims[tokenClaimsAudienceStr].(string)
		id := token.Claims[tokenClaimsJtiStr].(string)
		privilege := token.Claims[tokenClaimsPrivilegeStr].(string)
		updatePassword := token.Claims[tokenClaimsUpdatePasswordOnlyStr].(bool)
		return &SecureTokenData{token, userName, privilege, updatePassword, id}, nil
	case *jwt.ValidationError: // something was wrong during the validation
		vErr := err.(*jwt.ValidationError)

		switch vErr.Errors {
		case jwt.ValidationErrorExpired:
			return nil, fmt.Errorf("Token expired: Get a new one")
		default:
			return nil, fmt.Errorf("Problem was found while parsing token: %v", err)
		}

	default: // something else went wrong
		return nil, fmt.Errorf("Problem was found while parsing token: %v", err)
	}
}

// IsPrivilegeOk : Verify that the given privilege matches the one that is associated with the user defined in the token
func IsPrivilegeOk(tokenString string, privilege string, ipAddr string, verifyKey *rsa.PublicKey) (bool, error) {
	err := am.IsValidPrivilege(privilege)
	if err != nil {
		return false, err
	}
	token, err := ParseToken(tokenString, ipAddr, verifyKey)
	if err != nil {
		return false, err
	}
	var entityName string
	if privilege == am.SuperUserPermission {
		entityName = defs.SuperUserGroupName
	} else if privilege == am.AdminPermission {
		entityName = defs.AdminGroupName
	} else {
		entityName = defs.UsersGroupName
	}
	if usersList.IsUserPartOfAGroup(entityName, token.UserName) {
		return true, nil
	}
	return false, fmt.Errorf("The privilege %v is not permitted for this operation", token.Privilege)
}

// IsUpdatePasswordOnlySet : Check if the UpdatePassword is set
func IsUpdatePasswordOnlySet(tokenString string, ipAddr string, verifyKey *rsa.PublicKey) (bool, error) {
	token, err := ParseToken(tokenString, ipAddr, verifyKey)
	if err != nil {
		return false, err
	}
	return token.UpdatePassword, nil
}

// IsItTheSameUser : Verify that the user associated with the token is the same as the given one
func IsItTheSameUser(tokenString string, userName string, ipAddr string, verifyKey *rsa.PublicKey) (bool, error) {
	SecureTokenData, err := ParseToken(tokenString, ipAddr, verifyKey)

	if err != nil {
		return false, err
	}
	if SecureTokenData.UserName == userName {
		return true, nil
	}
	return false, nil
}
