// Package defs : This package is responsible for the definition of all the common variables used by the libsecurity-go library
package defs

import (
	"crypto/rand"
	"math/big"
	"time"

//	"io/ioutil"
//	"testing"
//	logger "github.com/ibm-security-innovation/libsecurity-go/logger"

	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

const (
	// RootUserName : define the root user name for the system
	RootUserName = "root"

	// AclAllEntryName : Saved name for ACL, the same as in Linux
	AclAllEntryName = "All"

	// ExtraCharStr : The only extra charcters that can be used and need to be used by passwords
	ExtraCharStr = "@#%^&()'-_+=;:"

	// SuperUserGroupName : Saved name for ACL super users group
	SuperUserGroupName = "Super-users"
	// AdminGroupName : Saved name for ACL administrators group
	AdminGroupName = "Admin"
	// UsersGroupName : Saved name for ACL users group
	UsersGroupName = "Users"

	// AmPropertyName : Saved name for the account properties
	AmPropertyName string = "AM"
	// AclPropertyName : Saved name for the ACL properties
	AclPropertyName string = "ACL"
	// OtpPropertyName : Saved name for the OTP properties
	OtpPropertyName string = "OTP"
	// OcraPropertyName : Saved name for the OCRA properties
	OcraPropertyName string = "OCRA"
	// PwdPropertyName : Saved name for the Password properties
	PwdPropertyName string = "PWD"
	// UmPropertyName : Saved name for the users/groups/resources properties
	UmPropertyName string = "UM"

	// PasswordThrottlingMiliSec : throttling delay in mili seconds when password does not match or if the entity does not exist
	// to handle timing atacks
	PasswordThrottlingMiliSec = 1000
	// ThrottleMaxRandomMiliSec : maximum random throttling delay in mili seconds to be added to PasswordThrottlingMiliSec in order to handle timing atacks
	ThrottleMaxRandomMiliSec = 10 // to avoid timimg attacks
)

var (
	// PropertiesName : which properties to store/load from secure storage
	PropertiesName = map[string]bool{
		AmPropertyName:   true,
		AclPropertyName:  true,
		OtpPropertyName:  true,
		OcraPropertyName: true,
		PwdPropertyName:  true,
		UmPropertyName:   true,
	}
)

// Serializer : virtual set of functions that must be implemented by each module
type Serializer interface {
	PrintProperties(data interface{}) string
	AddToStorage(prefix string, data interface{}, storage *ss.SecureStorage) error
	ReadFromStorage(prefix string, storage *ss.SecureStorage) (interface{}, error)
	IsEqualProperties(d1 interface{}, d2 interface{}) bool
}

// SerializersMap : hash structure, the key is the module property name
type SerializersMap map[string]Serializer

// Serializers : create the SerializersMap structure
var Serializers = make(SerializersMap)

// TimingAttackSleep : sleep for given delay in mili seconds plus random delay in the given rabge: to handle timing attacks
func TimingAttackSleep(baseSleepMiliSec int64, maxRandomMiliSec int64) {
	if maxRandomMiliSec <= 0 {
		maxRandomMiliSec = 1
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(maxRandomMiliSec))
	if err != nil {
		nBig = big.NewInt(maxRandomMiliSec / 2)
	}
	time.Sleep(time.Duration(nBig.Int64()+baseSleepMiliSec) * time.Millisecond)
}

// GetBeginningOfTime : return 1/1/1970
func GetBeginningOfTime() time.Time {
	return time.Date(1970, time.January, 1, 1, 0, 0, 0, time.Local)
}
