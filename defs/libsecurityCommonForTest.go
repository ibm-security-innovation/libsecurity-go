// Package defs : This package is responsible for the common tests
package defs

import (
	"io/ioutil"
	"testing"

	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

// StoreLoadTest : common store load testing for all the different properties
func StoreLoadTest(t *testing.T, userData interface{}, propertyName string) {
	filePath := "./tmp.txt"
	key := "key"
	secret := []byte("12345678")
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	storage, err := ss.NewStorage(secret, false)
	if err != nil {
		t.Errorf("Fatal error: can't create storage, error: %v", err)
	}
	s := Serializers[propertyName]	
	err = s.AddToStorage(key, userData, storage)
	if err != nil {
		t.Fatal("Fatal error: can't add to storage, error:", err)
	}
	err = s.AddToStorage(key, nil, storage)
	if err == nil {
		t.Errorf("Test fail: Successfully add undefined property to storage")
	}
	err = s.AddToStorage(key, userData, nil)
	if err == nil {
		t.Errorf("Test fail: Successfully add  property to nil storage")
	}
	storage.StoreInfo(filePath)	
	storage, err = ss.LoadInfo(filePath, secret)
	if err != nil {
		t.Fatal("Fatal error: can't load from storage, error:", err)
	}
	_, err = s.ReadFromStorage(key, nil)
	loadStorage := storage.GetDecryptStorageData()

	if err == nil {
		t.Fatal("Fatal error: Read pass but storage is nil")
	}
	_, err = s.ReadFromStorage("", loadStorage)
	if err == nil {
		t.Fatal("Fatal error: Read pass but the key is empty")
	}
	_, err = s.ReadFromStorage(key, loadStorage)
	if err != nil {
		t.Fatal("Fatal error: can't load from storage, error:", err)
	}
	data, err := s.ReadFromStorage(key, loadStorage)
	if err != nil {
		t.Fatal("Fatal error: can't read from storage, error:", err)
	}
	if s.IsEqualProperties(userData, data) == false {
		t.Fatal("Fatal error: Data read from storage:", s.PrintProperties(data), "is not equal to the one that was write to storage:", userData)
	}
	if s.IsEqualProperties(userData, "") == true {
		t.Fatal("Fatal error: unequal properies were found equal")
	}
	logger.Trace.Println("Data:", s.PrintProperties(data))
}
