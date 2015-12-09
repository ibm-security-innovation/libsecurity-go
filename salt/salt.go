// The salt package provides salting services for anyone who uses passwords
package salt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"hash"
	"io"

	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
)

const (
	defaultOutputLen        = 128
	defaultSaltLen          = 8
	defaultNumOfItterations = 1

	minOutputLen        = 6
	minSaltLen          = 0
	maxSaltLen          = 128
	minNumOfItterations = 1
)

var defaultHashFunc = sha1.New

type Salt struct {
	Secret     []byte
	Salt       []byte
	OutputLen  int              // Number of digits in the code. Default is 6
	Iterations int              // Number of iterations to run the hash function, Default is 64
	Digest     func() hash.Hash // Digest type, Default is sha1
}

func (s Salt) String() string {
	ret := fmt.Sprintf("Salt info: secret: %v, salt: %v, iterations: %v, output len: %v, digest: %v",
		string(s.Secret), string(s.Salt), s.Iterations, s.OutputLen, s.Digest)
	return ret
}

func isOutputLenValid(val int) error {
	if val < minOutputLen {
		return fmt.Errorf("Salt struct is not valid, the used output length %v is less than the minimum %v", val, minOutputLen)
	}
	return nil
}

func isDigestValid(digest func() hash.Hash) error {
	if digest == nil {
		return fmt.Errorf("Salt struct is not valid, it must have a hash function, but the current hash is nil")
	}
	return nil
}

func isSecretValid(secret []byte, minSecretLen int, maxSecretLen int) error {
	if len(secret) < minSecretLen || len(secret) > maxSecretLen {
		return fmt.Errorf("Secret string has illegal length %v, length must be between %v and %v", len(secret), minSecretLen, maxSecretLen)
	}
	return nil
}

func isSaltValid(salt []byte) error {
	if len(salt) < minSaltLen || len(salt) > maxSaltLen {
		return fmt.Errorf("Salt string has illegal length %v, length must be between %v and %v", len(salt), minSaltLen, maxSaltLen)
	}
	return nil
}

func isNumOfIterationsValid(val int) error {
	if val < minNumOfItterations {
		return fmt.Errorf("Salt struct is not valid, the number of iterations %v is less than the minimum %v", val, minNumOfItterations)
	}
	return nil
}

func (salt Salt) isValid(minSecretLen int, maxSecretLen int) error {
	err := isSecretValid(salt.Secret, minSecretLen, maxSecretLen)
	if err != nil {
		return err
	}
	err = isSaltValid(salt.Salt)
	if err != nil {
		return err
	}
	err = isOutputLenValid(salt.OutputLen)
	if err != nil {
		return err
	}
	err = isNumOfIterationsValid(salt.Iterations)
	if err != nil {
		return err
	}
	err = isDigestValid(salt.Digest)
	if err != nil {
		return err
	}
	return nil
}

// The default Salt: use sha1, output length 16 bytes
func NewSalt(secret []byte, minSecretLen int, maxSecretLen int, salt []byte) (*Salt, error) {
	err := isSecretValid(secret, minSecretLen, maxSecretLen)
	if err != nil {
		return nil, err
	}
	err = isSaltValid(salt)
	if err != nil {
		return nil, err
	}
	return &Salt{
		secret,
		salt,
		defaultOutputLen,
		defaultNumOfItterations,
		defaultHashFunc,
	}, nil
}

func GenerateSaltedPassword(pwd []byte, minSecretLen int, maxSecretLen int, saltData []byte, passwordLen int) ([]byte, error) {
	mySalt, err := NewSalt([]byte(pwd), minSecretLen, maxSecretLen, saltData)
	if err != nil {
		return nil, err
	}
	if passwordLen != -1 {
		mySalt.OutputLen = passwordLen
	}
	return mySalt.Generate(minSecretLen, maxSecretLen)
}

// Return a generated salted password and the used salt from a given password
func GeneratePasswordWithRndSalt(pass string, minSecretLen int, maxSecretLen int) ([]byte, []byte, error) {
	salt, err := GetRandomSalt(defaultSaltLen)
	if err != nil {
		return nil, nil, err
	}
	s, err := NewSalt([]byte(pass), minSecretLen, maxSecretLen, salt)
	if err != nil {
		return nil, nil, err
	}
	saltedPass, err := s.Generate(minSecretLen, maxSecretLen)
	return saltedPass, salt, err
}

// Return the encrypted data for a given salt and secret
// The way to add salt is: secret + salt
//TODO: output len from right or from left
func (salt Salt) Generate(minSecretLen int, maxSecretLen int) ([]byte, error) {
	err := salt.isValid(minSecretLen, maxSecretLen)
	if err != nil {
		return []byte(""), err
	}
	h := salt.Digest()

	data := salt.Secret
	for i := 0; i < salt.Iterations; i++ {
		data = append(data, salt.Salt...)
		h.Write(data)
		data = h.Sum(nil)
	}
	logger.Trace.Println("data:", data)
	len := len(data)
	if len > salt.OutputLen {
		len = salt.OutputLen
	}
	ret := data[0:len]
	return ret, nil
}

func (salt Salt) Match(ref []byte, minSecretLen int, maxSecretLen int) (bool, error) {
	res, _ := salt.Generate(minSecretLen, maxSecretLen)
	ok := bytes.Equal(res, ref)
	return ok, nil
}

func GetRandomSalt(size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("Size was %v, must be larger than 1", size)
	}
	buf := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Errorf("random read failed: %v", err))
	}
	return buf, nil
}
