package storage_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

const (
	keyFmt  = "The key is: %v"
	dataFmt = "The data is (sum of key digits): %v"
)

var (
	aesSecretLen = 32
)

func init() {
}

func generateSecureStorage() (*ss.SecureStorage, []byte) {
	var secret []byte

	secret = make([]byte, aesSecretLen)
	io.ReadFull(rand.Reader, secret)
	storage, _ := ss.NewStorage(secret, false)
	for i := 0; i < 10; i++ {
		keyText := fmt.Sprintf(keyFmt, i)
		dataText := fmt.Sprintf(dataFmt, i*10+1)
		storage.AddItem(keyText, dataText)
	}
	return storage, secret
}

func playWithSecureStorage(storage *ss.SecureStorage, secret []byte) {
	fileName := "try.txt"
	defer os.Remove(fileName)
	err := storage.StoreInfo(fileName)
	if err != nil {
		fmt.Println("Error while saving:", err)
	}

	fmt.Println("Original data:")
	fmt.Println(storage.GetDecryptStorageData())

	keyText := fmt.Sprintf(keyFmt, 1)
	err = storage.RemoveItem(keyText)
	if err != nil {
		fmt.Println("Error while remove key:", err)
	}

	fmt.Println("After removing:")
	fmt.Println(storage.GetDecryptStorageData())

	sd, err := ss.LoadInfo(fileName, secret)
	if err != nil {
		fmt.Println("Error while reading:", err)
	}
	fmt.Println("The data that was read from file:", fileName)
	fmt.Println(sd.GetDecryptStorageData())
}

// This example shows how to create a new secure storage list.
// 1. Add 10 new items with the following format: key: "The key is: %v", Value: "The data is (sum of key digits): %v"
// 2. Print it
// 3. Save it to file
// 4. Remove 1 item from it
// 5. Print it again
// 6. Read the saved storage
// 7. Print it again
func Example_storage() {
	storage, secret := generateSecureStorage()
	playWithSecureStorage(storage, secret)
}
