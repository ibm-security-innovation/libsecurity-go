package storage

import (
	"bytes"
	"crypto/rand"
	//	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

const (
	baseSecret  = "AaBb@1234567890123456"
	baseSecret1 = "AaBc;1234567890111111"
)

var (
	RandomStr string
)

func init() {
	val := make([]byte, 20)
	io.ReadFull(rand.Reader, val)
	RandomStr = string(bytes.Replace(val, []byte{0}, []byte{'a'}, -1))
}

// Verify that adding the same item key with different values reflects it the results
// Verify that getting a removed item will return an error
func Test_checkAddRemoveItemToSecureStorage(t *testing.T) {
	keys := []string{"k1", "k2 is the best key in here", "k1", RandomStr}
	values := []string{"v1", "v2 is the answer to the question of k2", "v3", RandomStr}
	secret := []byte(baseSecret)

	s, _ := NewStorage(secret, true)
	for i, key := range keys {
		s.AddItem(key, values[i])
		val, err := s.GetItem(key)
		if err != nil {
			t.Errorf("Test fail: Valid key: '%v' (idx %v) was not presented, error: %v", key, i, err)
		} else if val != values[i] {
			t.Errorf("Test fail: The recieved value: '%v' was not as expected '%v'", []byte(val), []byte(values[i]))
		}
	}
	for i, key := range keys {
		val, err := s.GetItem(key)
		if err != nil {
			t.Errorf("Test fail: Valid key: '%v' (idx %v) was not presented, error: %v", key, i, err)
		} else if val != values[i] && i != 0 {
			t.Errorf("Test fail: The recieved value: '%v' was not as expected '%v'", val, values[i])
		} else if val == values[i] && i == 0 {
			t.Errorf("Test fail: The recieved value: '%v' for key '%v' was changed", val, key)
		}
	}
	for _, key := range keys {
		s.RemoveItem(key)
		_, err := s.GetItem(key)
		if err == nil {
			t.Errorf("Test fail: Removed key: '%v' return a value", key)
		}
	}
}

// Verify that secure storage saved to file is equal to the one loaded from that file
// Verify that wrong secret return an error when reading a secure storage
// Verify that wrong signature return an error when reading a secure storage
func Test_checkStoreLoadSecureStorageFile(t *testing.T) {
	keys := []string{"k1", "k2", "k3"}
	values := []string{"v1", "v2", "v3"}
	secret := []byte(baseSecret)
	fileName := "./tmp.txt"
	secret1 := []byte(baseSecret1)

	s, _ := NewStorage(secret, true)
	for i, key := range keys {
		s.AddItem(key, values[i])
	}
	s.StoreInfo(fileName)
	defer os.Remove(fileName)
	s1, err := LoadInfo(fileName, secret)
	if err != nil {
		t.Errorf("Test fail: Read secure storage from file fail, error: %v", err)
		t.FailNow()
	}
	if reflect.DeepEqual(s.Data, s1.Data) == false {
		s1.secret = secret // to allow decryption
		t.Errorf("Test fail: The original secure storage: '%v' is not equal after store and load it: '%v'",
			s.GetDecryptStorageData(), s1.GetDecryptStorageData())
	}

	_, err = LoadInfo(fileName, secret1)
	if err == nil {
		t.Errorf("Test fail: Successfully read secure storage from file while using wrong secret")
	}

	// currpt the file data
	data, _ := ioutil.ReadFile(fileName)
	data[40] = 'x'
	data[41] = 'x'
	ioutil.WriteFile(fileName, data, FilePermissions)

	_, err = LoadInfo(fileName, secret)
	if err == nil {
		t.Errorf("Test fail: Successfully read secure storage from file while the file was currpted")
	}
}
