// Initialization services.
//
// Utility that generates an initial secureStorage file to be used later by all other components
// The usage is:
//	usage: generate_login_file
//	 -generate-rsa=false: Generate RSA private/public files ('key.private', 'key.pub')
//	 -login-file="./data.txt": First data file that includes the root user
//	 -password="root": Root password
//	 -secure-key="./secureKey": secure key file path
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	am "ibm-security-innovation/libsecurity-go/accounts"
	stc "ibm-security-innovation/libsecurity-go/defs"
	en "ibm-security-innovation/libsecurity-go/entity"
	"ibm-security-innovation/libsecurity-go/password"
	"ibm-security-innovation/libsecurity-go/salt"
	ss "ibm-security-innovation/libsecurity-go/storage"
)

const (
	minPassLen    = 10
	extraCharStr  = "@#%^&()'-_+=;:"
	digitStr      = "0123456789"
	minRegularCnt = 4
	minDigits     = 2
	minExtraChars = 2
	saltLen       = 8

	rsaPrivateKeyFileName = "key.private"
	rsaPublicKeyFileName  = "key.pub"
)

var (
	passwordRules string
)

func init() {
	passwordRules = fmt.Sprintf("Password must include at least %v characters, with at least %v regular charachters, %v extra characters from: '%v' and at least %v digits",
		minPassLen, minRegularCnt, minExtraChars, extraCharStr, minDigits)
}

func usage() {
	strs := strings.Split(os.Args[0], "/")
	fmt.Fprintf(os.Stderr, "usage: %s\n", strs[len(strs)-1])
	flag.PrintDefaults()
	os.Exit(2)
}

func checkRootPasswordStrength(pass string) bool {
	extraCnt := 0
	digitCnt := 0

	for _, c := range extraCharStr {
		extraCnt += strings.Count(pass, string(c))
	}
	for _, c := range digitStr {
		digitCnt += strings.Count(pass, string(c))
	}
	if len(pass) < minPassLen || extraCnt < minExtraChars || digitCnt < minDigits ||
		len(pass)-extraCnt-digitCnt < minRegularCnt {
		fmt.Printf("Error: password: '%v', password length: %v, number of extra characters: %v, number of digits: %v\n", pass, len(pass), extraCnt, digitCnt)
		return false
	}
	return true
}

// Generate a new secure storage minimal file that includes the root user with
// basic Account Management: the root user privilege and password
func createBasicFile(stFilePath string, name string, pass string, key []byte) {
	saltStr, _ := salt.GetRandomSalt(saltLen)
	_, err := salt.GenerateSaltedPassword([]byte(pass), password.MinPasswordLength, password.MaxPasswordLength, saltStr, -1)
	if err != nil {
		log.Fatalf("Error: can't generate salted password for '%v' user, error: %v", name, err)
	}
	ul := en.NewEntityManager()
	ul.AddUser(name)
	amUser, _ := am.NewUserAm(am.SuperUserPermission, []byte(pass), saltStr)
	ul.AddPropertyToEntity(name, stc.AmPropertyName, amUser)
	ul.StoreInfo(stFilePath, key)
}

// Generate RSA public and private keys to the given file name
func generateRSAKeys(rsaPrivateKeyFileName string, rsaPublicKeyFileName string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Error: can't generate rsa key, error: %v", err)
	}
	privateASN1 := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateASN1,
	})
	ioutil.WriteFile(rsaPrivateKeyFileName, privateBytes, 0644)

	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Error: can't generate rsa public key from the private key, error: %v", err)
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	ioutil.WriteFile(rsaPublicKeyFileName, pubBytes, 0644)
	fmt.Println("Generate RSA files:", rsaPrivateKeyFileName, "And", rsaPublicKeyFileName)
}

func main() {
	defaultRootPassword := stc.RootUserName

	secureKeyFileNamePath := flag.String("secure-key", "./secureKey", "secure key file path")
	loginFilePath := flag.String("storage-file", "./data.txt", "First storage file that includes the root user")
	rootPassword := flag.String("password", defaultRootPassword, "Root password")
	str := fmt.Sprintf("Generate RSA private/public files ('%s', '%s')", rsaPrivateKeyFileName, rsaPublicKeyFileName)
	generateRSA := flag.Bool("generate-rsa", false, str)
	flag.Parse()
	if flag.NArg() > 0 {
		usage()
	}

	if *rootPassword == defaultRootPassword {
		fmt.Printf("Error: The root password must be set (and not to '%v')\n", defaultRootPassword)
		usage()
	}
	if checkRootPasswordStrength(*rootPassword) == false {
		log.Fatalf("Error: The root password must be more complex: %v", passwordRules)
	}

	key := ss.GetSecureKey(*secureKeyFileNamePath)
	createBasicFile(*loginFilePath, stc.RootUserName, *rootPassword, key)
	fmt.Println("The generated file name is:", *loginFilePath)
	if *generateRSA {
		generateRSAKeys(rsaPrivateKeyFileName, rsaPublicKeyFileName)
	}
}
