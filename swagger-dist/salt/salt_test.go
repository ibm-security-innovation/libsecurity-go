package salt

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"
)

// TODO not tested: static external tests for iterations other than 1 (I couldn't find an online site)

const (
	testMinPwdLen = 4
	testMaxPwdLen = 255
)

type SaltRun struct {
	salt   *Salt
	result []byte
}

func (s SaltRun) String() string {
	return fmt.Sprintf("%v, result: %v", s.salt, s.result)
}

var BaseSecret = []byte("ABCD")
var BaseSalt = []byte("A1B2")

var referenceRunsSalt []SaltRun

func init() {
	referenceRunsSalt = initRefSalt()
}

func initRefSalt() []SaltRun {
	var refRunsSalt []SaltRun
	secrets := []string{"", "ABCD", "hello"}
	salts := []string{"", "A1B2", "a12b34"}
	hashes := []func() hash.Hash{sha1.New, sha256.New, md5.New, nil}
	maxOutputLength := minOutputLen + 2

	for _, sc := range secrets {
		for _, sl := range salts {
			for _, d := range hashes {
				for ol := 0; ol < maxOutputLength; ol++ {
					for i := minNumOfItterations - 1; i < minNumOfItterations*100; i += 10 {
						salt, err := NewSalt([]byte(sc), testMinPwdLen, testMaxPwdLen, []byte(sl))
						serr := isSecretValid([]byte(sc), testMinPwdLen, testMaxPwdLen)
						slerr := isSaltValid([]byte(sl))
						if err == nil && (serr != nil || slerr != nil) {
							fmt.Println("Error while initializing")
							panic(fmt.Errorf("Initialize failed: initialize was done successfully but the input is invalid: %v", salt))
						}
						if err != nil && serr == nil && slerr == nil {
							fmt.Println("Error while initializing")
							panic(fmt.Errorf("Initialize failed: input is valid %v, but error found: %v", salt, err))
						}
						if err == nil {
							salt.OutputLen = ol
							salt.Digest = d
							salt.Iterations = i
							res, err := salt.Generate(testMinPwdLen, testMaxPwdLen)
							derr := isDigestValid(d)
							olerr := isOutputLenValid(ol)
							ierr := isNumOfIterationsValid(i)
							if err != nil && derr == nil && olerr == nil && ierr == nil {
								fmt.Println("Error while initializing")
								panic(fmt.Errorf("Initialize failed: Try to generate salted code for valid input %v, but error found: %v", salt, err))
							} else if err == nil && (derr != nil || olerr != nil || ierr != nil) {
								fmt.Println("Error while initializing")
								panic(fmt.Errorf("Initialize failed salted code was generated successfully for invalid input: %v\n", salt)) // " secret (%v), salt(%v), digest (%v), output len (%v)\n", sc, sl, d, ol))
							} else if err == nil {
								refRunsSalt = append(refRunsSalt, SaltRun{salt, res})
							}
						}
					}
				}
			}
		}
	}
	return refRunsSalt
}

// Verify that Different parameters (secret keys, salt, output len, input, digests) result with different generated password
func Test_SaltParamesChanged(t *testing.T) {
	res := make(map[string]SaltRun)
	for _, data := range referenceRunsSalt {
		_, exists := res[string(data.result)]
		if exists {
			t.Error("Runs with different salt parameters return the same password:\nFirst run:", res[string(data.result)], "\nSecond run:", data)
		} else {
			res[string(data.result)] = data
		}
	}
}

// Verify that the same parameters (secret keys, salt, output len, input, digests) result with the same generated password
func Test_SaltRepetitation(t *testing.T) {
	for _, data := range referenceRunsSalt {
		ok, _ := data.salt.Match(data.result, testMinPwdLen, testMaxPwdLen)
		if !ok {
			t.Error("Runs with the same salt parameters:", data, "return a different password")
		}
	}
}

type testHash struct {
	Digest    func() hash.Hash
	Iteration int
	Password  string
}

// Results are from http://www.lorem-ipsum.co.uk/hasher.php
func Test_StaticCalculationSalting(t *testing.T) {
	var testsFor_ABCD_A1B2 = []testHash{{sha1.New, 1, "f877eed103f74c751952861e0630e643c4ec1eaa"},
		{md5.New, 1, "dcfdf079664f00c2ad0d1e348b070bd5"},
		{sha256.New, 1, "a193d7d1ba2253b712d13a0dd27bd7dfddcf04a6c8d904ae7e0e9ba2ced0f8fb"}}

	for i, test := range testsFor_ABCD_A1B2 {
		salt, err := NewSalt([]byte("ABCD"), 4, 128, []byte("A1B2"))
		if err != nil {
			t.Error("Test fail: Can't initialize Salt, error:", err)
			t.FailNow()
		}
		salt.Iterations = test.Iteration
		salt.Digest = test.Digest
		ref, err := hex.DecodeString(test.Password)
		if err != nil {
			t.Error("Test fail, can't convert", test.Password, "to bytes")
		}
		ok, err := salt.Match(ref, testMinPwdLen, testMaxPwdLen)
		if err != nil {
			t.Error("Test fail, error:", err)
		} else if !ok {
			t.Error("Test", i, "Fail: Expected external password", ref,
				"did not matched calculated password")
		}
	}
}

func Test_RandomSalt(t *testing.T) {
	for i := -10; i < 1000; i += 10 {
		salt, err := GetRandomSalt(i)
		if err == nil && i < 0 {
			t.Error("Test fail: get random salt:", salt, "for size of:", i, ", but it is illegal")
		} else if err != nil && i >= 0 {
			t.Error("Test fail: Generating of random salt for size", i, " fail, error:", err)
		}
	}
}
