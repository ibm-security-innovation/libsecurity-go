package salt_test

import (
	"crypto/md5"
	"fmt"
	"hash"

	"ibm-security-innovation/libsecurity-go/salt"
)

const (
	minSecretLen = 1
	maxSecretLen = 255
)

var (
	BasicSecret = []byte("ABCDABCD")
	BasicSalt   = []byte("A1B2")
)

func getSaltExample(secret, sa []byte, iter int, f func() hash.Hash, size int) ([]byte, error) {
	mySalt, err := salt.NewSalt(secret, minSecretLen, maxSecretLen, sa)
	if err != nil {
		return nil, err
	}
	mySalt.Iterations = iter
	mySalt.OutputLen = size
	mySalt.Digest = f
	return mySalt.Generate(minSecretLen, maxSecretLen)
}

func getRandomSaltExample(secret []byte, saltLen int, iter int, f func() hash.Hash, size int) ([]byte, []byte, error) {
	salting, _ := salt.GetRandomSalt(saltLen)
	mySalt, err := salt.NewSalt(secret, minSecretLen, maxSecretLen, salting)
	if err != nil {
		return nil, nil, err
	}
	mySalt.Iterations = iter
	mySalt.OutputLen = size
	mySalt.Digest = f
	res, err := mySalt.Generate(minSecretLen, maxSecretLen)
	if err != nil {
		return nil, nil, err
	} else {
		return res, salting, nil
	}
}

// This example shows how to generate a saltetd password from a given password and default salt
func ExampleGenerateSaltedPassword() {
	pass := "MyPassword"
	res, err := salt.GenerateSaltedPassword([]byte(pass), minSecretLen, maxSecretLen, BasicSalt, -1)
	if err != nil {
		fmt.Println("GenerateSaltedPassword failed, error:", err)
	} else {
		fmt.Printf("* Generate basic salted password from a given password: '%v', using the default parameters (sha1, show full password, 1 iteration and random salt: %v) is: %v", pass, BasicSalt, res)
	}
}

// This example shows how to generate a randomly salted secret contain 8 characters, using hash function of md5 and 3 iterations of calculations
func ExampleGetRandomSalt() {
	iter := 3
	f := md5.New
	size := 8
	saltLen := 32

	randSalt, _ := salt.GetRandomSalt(saltLen)
	mySalt, err := salt.NewSalt(BasicSecret, minSecretLen, maxSecretLen, randSalt)
	if err != nil {
		fmt.Println("Error while creating new salt structure:", err)
	}
	mySalt.Iterations = iter
	mySalt.OutputLen = size
	mySalt.Digest = f
	res, err := mySalt.Generate(minSecretLen, maxSecretLen)
	if err != nil {
		fmt.Println("GetRandomSaltExample failed, error:", err)
	} else {
		fmt.Println("* Salted password of secret key:", string(BasicSecret), ",random salt length:", saltLen, randSalt,
			"with", iter, "iterations, output password length:", size, "bytes and MD5 function is:", res)
	}
}
