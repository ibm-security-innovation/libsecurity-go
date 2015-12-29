// Package storage : The secureStorage package provides implementation of Secure storage services: Persistence mechanism based on AES Encryption of key-value pairs within a signed file.
//
// The secure storgae allows maintaining data persistently and securely.
// 	The implementation of the secure storage is based on encrypted key-value pairs that are stored
//	 in signed files to guarantee that the data is not altered or corrupted.
//	- Both the key and the value are encrypted when they are added to the storage using an Advanced Encryption Standard (AES) algorithm.
//	- Each time a new secure storage is generated, a secret supplied by the user accompanies it
//	  and is used in all HMAC and AES calculations related to that storage. To make it difficult for a third party to decipher or use the stored data,
//	  Cipher Block Chaining (CBC) mode is used to ensure that multiple independent encryptions of the same data with the same key have different results.
//	  That is, when a block with the same piece of plain text is encrypted with the same key, the result is always different.
//	- To implement a time efficient secure storage with keys, that is, to identify keys that are
//	  already stored without decrypting the entire storage, and when such a key is identified replacing its value, a two step mechanism is used.
//	  The first time a key is introduced, a new IV is drawn, the key is 'HMAC'ed with the secret and is stored with the IV as the value (1st step).
//	  The original key is encrypted with the drawn IV and stored again, this time with the value that is encrypted with its own random IV (2nd step).
//	  The next time that same key is stored, the algorithm, identifies that it already exists in the storage, pulls out the random IV that was stored in the 1st step,
//	  finds the 2nd step storage of that key and replaces its value with the new encrypted one.
//	- To guarantee that the data is not altered or corrupted, the storage is signed using HMAC. The signature is added to the secure storage. When the storage is loaded,
//	  the HMAC is calculated and compared with the stored signature to verify that the file is genuine.
package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"unicode"

	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	"github.com/ibm-security-innovation/libsecurity-go/salt"
)

const (
	// FilePermissions : linux style read/write for the owner
	FilePermissions = 0600
	// MaxSaltLen : the maximum salting string length
	MaxSaltLen = 16
	// SaltLen : the default salting string length
	SaltLen = 8
	// SecretLen : the default secret string length
	SecretLen    = 16
	minSecretLen = 8
	maxSecretLen = 255
	// SaltData : the default salting string
	SaltData = "Ravid"

	extraCharStr  = "@#%^&()'-_+=;:"
	minUpperCase  = 2
	minLowerCase  = 2
	minDigits     = 2
	minExtraChars = 1
)

var (
	lock          sync.Mutex
	aesKeySize    = make(map[int]interface{})
	aesKeySizeStr string

	nullChar = byte(0)
)

func init() {
	aesKeySize[16] = ""
	aesKeySize[24] = ""
	aesKeySize[32] = ""
	var s []byte
	for k := range aesKeySize {
		s = append(s, fmt.Sprintf("%v ", k)...)
	}
	aesKeySizeStr = string(s)
}

// SecureDataMap : hash to map the modules data
type SecureDataMap map[string]string

// SecureStorage : structure that holds all the secure data to be store/read from the storage include the calculated signature (the secret is not stored on the disk)
type SecureStorage struct {
	Salt   []byte
	Sign   []byte
	Data   SecureDataMap
	secret []byte
}

func (s SecureStorage) String() string {
	sArray := make([]string, 0, len(s.Data))

	for key, value := range s.Data {
		sArray = append(sArray, fmt.Sprintf("key: %v, value: %v", key, value))
	}
	return fmt.Sprintf("Data: %v", sArray)
}

func getSaltedPass(secret, saltData []byte) []byte {
	pass, _ := salt.GenerateSaltedPassword(secret, minSecretLen, maxSecretLen, saltData, SecretLen)
	return bytes.Replace(pass, []byte{'0'}, []byte{'a'}, -1)
}

// NewStorage : Create a new storage using the given secret
func NewStorage(secret []byte, checkSecretStrength bool) (*SecureStorage, error) {
	err := isValidData(secret)
	if err != nil {
		return nil, err
	}
	err = isSecretStrengthOk(string(secret))
	if err != nil && checkSecretStrength {
		return nil, err
	}
	saltData, _ := salt.GetRandomSalt(SaltLen)
	pass := getSaltedPass(secret, saltData)
	s := SecureStorage{Data: make(SecureDataMap), secret: pass, Salt: saltData}
	return &s, nil
}

// IsSecretMatch : Verify if the given secret match the secure stiorage secret use throttling
func (s *SecureStorage) IsSecretMatch(secret []byte) bool {
	pass := getSaltedPass(secret, s.Salt)
	return subtle.ConstantTimeCompare(s.secret, pass) == 1
}

func manipulateSecureKey(key []byte, saltData []byte) []byte {
	return pbkdf2.Key(key, saltData, 4096, 32, sha256.New)
}

// GetSecureKey : Read a secure key from the given file, process it with cryptographic manipulations  and return it
func GetSecureKey(secureKeyFilePath string) []byte {
	secureKey, err := ioutil.ReadFile(secureKeyFilePath)
	if err != nil {
		logger.Error.Fatal("Error reading secure key file:", secureKeyFilePath)
	}
	saltLen := len(secureKey)
	if saltLen > MaxSaltLen {
		saltLen = MaxSaltLen
	}
	return manipulateSecureKey(secureKey, []byte(SaltData))
}

func isValidData(secret []byte) error {
	return isValidSecret(secret)
}

func isValidSecret(secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("key length must be at least 1 byte long")
	}
	return nil
}

// AddItem : Add (or replace) to the storage a new item using the given key and value
func (s *SecureStorage) AddItem(key string, value string) error {
	lock.Lock()
	defer lock.Unlock()

	hKey, rKey, err := s.generateRandomToKey(key)
	if err != nil {
		return err
	}
	cipherKey, err := s.encrypt([]byte(key), true, rKey)
	if err != nil {
		return err
	}
	cipherData, err := s.encrypt([]byte(value), false, "")
	if err != nil {
		return err
	}
	s.Data[hKey] = rKey
	s.Data[cipherKey] = cipherData
	return nil
}

// GetItem : Return from storage the item that is associated with the given key
func (s *SecureStorage) GetItem(key string) (string, error) {
	lock.Lock()
	defer lock.Unlock()

	_, rKey, err := s.getRandomFromKey(key)
	if err != nil {
		return "", err
	}
	cipherKey, err := s.encrypt([]byte(key), true, rKey)
	if err != nil {
		return "", err
	}
	val, exist := s.Data[cipherKey]
	if !exist {
		return "", fmt.Errorf("key '%v' was not found", key)
	}
	value, err := s.decrypt([]byte(val))
	if err != nil {
		return "", err
	}
	ret, err := s.extractDataFromEncodedString(value)
	if err != nil {
		return "", err
	}
	return ret, nil
}

// RemoveItem : Remove from the storage the item that is associated with the given key
func (s *SecureStorage) RemoveItem(key string) error {
	lock.Lock()
	defer lock.Unlock()

	hKey, rKey, err := s.getRandomFromKey(key)
	if err != nil {
		return err
	}
	delete(s.Data, hKey)
	cipherKey, err := s.encrypt([]byte(key), true, rKey)
	if err != nil {
		return err
	}
	_, exist := s.Data[cipherKey]
	if !exist {
		return fmt.Errorf("key '%v' was not found", key)
	}
	delete(s.Data, cipherKey)
	return nil
}

func (s SecureStorage) encrypt(text []byte, fixedIv bool, inIv string) (string, error) {
	var b string

	block, err := aes.NewCipher(s.secret)
	if err != nil {
		return "", fmt.Errorf("during encryption: '%v', error: %v", text, err)
	}

	data := text
	for {
		b = base64.StdEncoding.EncodeToString(data)
		if len(b)%aes.BlockSize == 0 {
			break
		}
		data = append(data, nullChar)
	}
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if fixedIv == false {
		_, err = io.ReadFull(rand.Reader, iv)
	} else {
		str := inIv + strings.Repeat("a", aes.BlockSize-len(inIv)+10)
		copy(iv, []byte(str)[:aes.BlockSize])
	}
	if err != nil {
		return "", fmt.Errorf("during encryption: '%v', error: %v", text, err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], []byte(b))
	ret := base64.StdEncoding.EncodeToString(ciphertext)
	return ret, nil
}

func (s SecureStorage) getHKey(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	hKey := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
	return hKey
}

func (s SecureStorage) getRandomFromKey(key string) (string, string, error) {
	hKey := s.getHKey(key)
	val, exist := s.Data[hKey]
	if !exist {
		return "", "", fmt.Errorf("key '%v' was not found", key)
	}
	return hKey, string(val), nil
}

func (s SecureStorage) generateRandomToKey(key string) (string, string, error) {
	hKey := s.getHKey(key)
	val := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, val)
	if err != nil {
		return "", "", err
	}
	hVal := base64.StdEncoding.EncodeToString(val)
	return hKey, hVal, nil
}

func (s SecureStorage) decrypt(text1 []byte) (string, error) {
	var data []byte

	// The decrypt may be called with un-encrypted data (the hash key to random,
	//   may be OK in some cases thus thiis has to be verified by the caller)
	defer func() (string, error) {
		if r := recover(); r != nil {
			return "", fmt.Errorf("during decryption: '%v'", text1)
		}
		return string(data), nil
	}()

	text, err := base64.StdEncoding.DecodeString(string(text1))
	if err != nil {
		return "", fmt.Errorf("during decryption: '%v', error: %v", text, err)
	}

	block, err := aes.NewCipher(s.secret)
	if err != nil {
		return "", fmt.Errorf("during decryption: '%v', error: %v", text, err)
	}
	if len(text) < aes.BlockSize {
		return "", fmt.Errorf("during decryption: ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	dtext := text[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dtext, dtext)
	return string(dtext), nil
}

func (s SecureStorage) calcHMac(data []byte, secret []byte) []byte {
	hmacHash := hmac.New(sha256.New, secret)
	hmacHash.Write(data)
	return hmacHash.Sum(nil)
}

// LoadInfo : Read a secure storage from file (JSON format), verify that the file is genuine
// by calculating the expected signature
func LoadInfo(fileName string, secret []byte) (*SecureStorage, error) {
	lock.Lock()
	defer lock.Unlock()

	var s SecureStorage
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("can't read Secure storage from file: '%v'", fileName)
	}
	json.Unmarshal(data, &s)
	sData, _ := json.Marshal(s.Data)
	pass := getSaltedPass(secret, s.Salt)
	sign := s.calcHMac(sData, pass)
	if bytes.Compare(sign, s.Sign) != 0 {
		return nil, fmt.Errorf("the file '%v' is not genuine", fileName)
	}
	s.secret = pass
	return &s, nil
}

// StoreInfo : Sign the secure storage and than store it to a given file path without the secret
func (s SecureStorage) StoreInfo(fileName string) error {
	tmpFileName := "./tmpA1B2.tr1"
	lock.Lock()
	defer lock.Unlock()

	sData, _ := json.Marshal(s.Data)
	s.Sign = s.calcHMac(sData, s.secret)
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("attempt to translate the Secure storage to JSON failed, error: %v", err)
	}
	// If a uniq file name is not found within 10 attemps assume that there is another problem
	for i := 0; i < 10; i++ {
		tmpFileName = tmpFileName + "Q#9"
		_, err := os.Stat(tmpFileName)
		if os.IsNotExist(err) {
			break
		}
	}
	err = ioutil.WriteFile(tmpFileName, data, FilePermissions)
	if err != nil {
		return fmt.Errorf("attempt to write the Secure storage to file '%v' failed, error: %v", fileName, err)
	}
	os.Rename(tmpFileName, fileName)
	return nil
}

func (s SecureStorage) extractDataFromEncodedString(data string) (string, error) {
	val := strings.Split(data, string(nullChar))
	ret, err := base64.StdEncoding.DecodeString(val[0])
	sLen := bytes.IndexByte(ret, 0)
	if sLen <= 0 {
		sLen = len(ret)
	}
	return string(ret[:sLen]), err
}

//GetDecryptStorageData : Get the decrypted storgae information
func (s SecureStorage) GetDecryptStorageData() *SecureStorage {
	data := make(SecureDataMap)

	for k, v := range s.Data {
		key1, err := s.decrypt([]byte(k))
		if err != nil {
			fmt.Println("Internal error in GetDecryptStorageData, key is:", k, "val", v)
		} else {
			key, _ := s.extractDataFromEncodedString(key1)
			value, _ := s.decrypt([]byte(v))
			val, _ := s.extractDataFromEncodedString(value)
			data[key] = val
		}
	}
	storage, err := NewStorage([]byte("aA12Bc@ junk secret!!!"), true)
	if err != nil {
		fmt.Printf("Internal Error: Can't generate storage, error: %v\n", err)
		return nil
	}
	if len(data) != 0 {
		for key, value := range data {
			if len(key) > 0 {
				storage.Data[key] = value
			}
		}
	}
	return storage
}

func isSecretStrengthOk(pass string) error {
	extraCnt := 0
	digitCnt := 0
	upperCaseCnt := 0
	lowerCaseCnt := 0

	for _, c := range extraCharStr {
		extraCnt += strings.Count(pass, string(c))
	}
	for _, c := range pass {
		if unicode.IsUpper(c) {
			upperCaseCnt++
		} else if unicode.IsLower(c) {
			lowerCaseCnt++
		} else if unicode.IsDigit(c) {
			digitCnt++
		}
	}
	if len(pass) < minSecretLen || extraCnt < minExtraChars || digitCnt < minDigits ||
		upperCaseCnt < minUpperCase || lowerCaseCnt < minLowerCase {
		return fmt.Errorf("The secure storage secret does not pass the secret strength test. In order to be strong, the password must contain at least %v characters, and include at least: %v digits, %v letters (%v must be upper-case and %v must be lower-case) and %v extra character from the list bellow.\nList of possible extra characters: '%v'",
			minSecretLen, minDigits, minUpperCase+minLowerCase, minUpperCase, minLowerCase, minExtraChars, extraCharStr)
	}
	return nil
}
