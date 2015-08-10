// The Token package: Enables the transfer of users' information between clients and servers using secure JSON Web Token (JWT) cookies
package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	am "ibm-security-innovation/libsecurity-go/accounts"
	//	"ibm-security-innovation/libsecurity-go/acl"
	stc "ibm-security-innovation/libsecurity-go/defs"
	en "ibm-security-innovation/libsecurity-go/entity"
	logger "ibm-security-innovation/libsecurity-go/logger"
)

const (
	TrusteerSecurityStr     = "Trusteer"
	tokenClaimsExpireStr    = "exp"
	tokenClaimsIssuerStr    = "iss"
	tokenClaimsAudienceStr  = "aud"
	tokenClaimsPrivilegeStr = "Privilege"
	tokenClaimsJtiStr       = "jti"
	tokenClaimsIPAddr       = "IPAddr"

	jwtLen = 128

	defaultTokenTimeExpirationMinutes = 30

	SuperUserPermission = "Super-user"
	AdminPermission     = "Admin"
	UserPermission      = "User"
)

var (
	jwtUniqId string

	usersList                                *en.EntityManager
	adminsGroup, superusersGroup, usersGroup *en.Entity
)

type TokenData struct {
	Token     *jwt.Token
	UserName  string
	Privilege string
	Id        string
}

func init() {
	jwtUniqId = generateJwt(jwtLen)

	usersList = en.NewEntityManager()

	usersList.AddGroup(stc.SuperUserGroupName)
	usersList.AddGroup(stc.AdminGroupName)
	usersList.AddGroup(stc.UsersGroupName)

	usersList.AddUserToGroup(stc.AdminGroupName, stc.SuperUserGroupName)
	usersList.AddUserToGroup(stc.UsersGroupName, stc.SuperUserGroupName)
	usersList.AddUserToGroup(stc.UsersGroupName, stc.AdminGroupName)
	usersList.AddUserToGroup(stc.SuperUserGroupName, stc.RootUserName)
}

func generateJwt(length int) string {
	val := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, val)
	if err != nil {
		logger.Error.Panic(fmt.Errorf("random read failed: %v", err))
	}
	for i, c := range val {
		val[i] = c%74 + 48 // printable chars
	}
	return string(val)
}

// Return the RSA private key from the given file
func GetPrivateKey(privateKeyFilePath string) ([]byte, *rsa.PrivateKey, error) {
	signKey, err := ioutil.ReadFile(privateKeyFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("Error reading private key file: '%v'", privateKeyFilePath)
	}

	block, _ := pem.Decode(signKey)
	if block == nil {
		return nil, nil, fmt.Errorf("Error found while decoding the private key")
	}
	r, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return signKey, r, nil
}

// Get from the given file a private key, calculate public keys based on that key and return all these (private and public) keys
func TokenSetUp(privateKeyFilePath string) ([]byte, []byte) {
	var err error

	signKey, pKey, err := GetPrivateKey(privateKeyFilePath)
	if err != nil {
		logger.Error.Fatal("Error reading private key file:", privateKeyFilePath)
	}

	t, err := x509.MarshalPKIXPublicKey(&pKey.PublicKey)
	if err != nil {
		logger.Error.Fatal("Error while calculating public key")
	}
	verifyKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: t,
	})
	return signKey, verifyKey
}

func getIpFromAddrStr(ipAddr string) string {
	addr := strings.Split(ipAddr, ":")
	if len(addr) >= 2 {
		val := addr[len(addr)-2]
		if strings.Contains(val, "localhost") {
			return "127.0.0.1"
		} else {
			return val
		}
	}
	return ""
}

// Generate a new signed token
func GenerateToken(name string, privilege string, ipAddr string, signKey []byte) (string, error) {
	// create a signer for rsa 256
	token := jwt.New(jwt.SigningMethodRS256)

	token.Claims[tokenClaimsExpireStr] = time.Now().Add(time.Minute * defaultTokenTimeExpirationMinutes).Unix()
	token.Claims[tokenClaimsIssuerStr] = TrusteerSecurityStr
	token.Claims[tokenClaimsAudienceStr] = name
	token.Claims[tokenClaimsJtiStr] = jwtUniqId
	token.Claims[tokenClaimsPrivilegeStr] = privilege
	token.Claims[tokenClaimsIPAddr] = getIpFromAddrStr(ipAddr)
	return token.SignedString(signKey)
}

// Parse the given token and verify that it holds the mandatory data
func ParseToken(tokenString string, ipAddr string, verifyKey []byte) (*TokenData, error) {
	token, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if token.Claims[tokenClaimsIssuerStr] != TrusteerSecurityStr {
				return nil, fmt.Errorf("The token is not valid: it was not issued by trusteer")
			}
			if token.Claims[tokenClaimsJtiStr] != jwtUniqId {
				return nil, fmt.Errorf("The token is not valid: wrong ID")
			}
			if token.Claims[tokenClaimsIPAddr] != getIpFromAddrStr(ipAddr) {
				return nil, fmt.Errorf("The token is not genuine")
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
		return &TokenData{token, userName, privilege, id}, nil
	case *jwt.ValidationError: // something was wrong during the validation
		vErr := err.(*jwt.ValidationError)

		switch vErr.Errors {
		case jwt.ValidationErrorExpired:
			return nil, fmt.Errorf("Token Expired, get a new one.")
		default:
			return nil, fmt.Errorf("Error while Parsing Token! %v", err)
		}

	default: // something else went wrong
		return nil, fmt.Errorf("Error while Parsing Token! %v", err)
	}
}

// Verify that the given privilege matches the one that is associated with the user defined in the token
func IsPrivilegeOk(tokenString string, privilege string, ipAddr string, verifyKey []byte) (bool, error) {
	err := am.IsValidPrivilege(privilege)
	if err != nil {
		return false, err
	}
	token, err := ParseToken(tokenString, ipAddr, verifyKey)
	if err != nil {
		return false, err
	}
	var entityName string
	if privilege == SuperUserPermission {
		entityName = stc.SuperUserGroupName
	} else if privilege == AdminPermission {
		entityName = stc.AdminGroupName
	} else {
		entityName = stc.UsersGroupName
	}
	if usersList.IsUserPartOfAGroup(entityName, token.UserName) {
		return true, nil
	}
	return false, fmt.Errorf("The privilege %v is not permited to this operation", token.Privilege)
}

// Verify that the user associated with the token is the same as the given one
func IsItTheSameUser(tokenString string, userName string, ipAddr string, verifyKey []byte) (bool, error) {
	tokenData, err := ParseToken(tokenString, ipAddr, verifyKey)

	if err != nil {
		return false, err
	}
	if tokenData.UserName == userName {
		return true, nil
	}
	return false, nil
}
