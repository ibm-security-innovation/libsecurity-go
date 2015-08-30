// This package is responsible for the definition of all the common variables used by the libsecurity-go library
package defs

import (
	ss "ibm-security-innovation/libsecurity-go/storage"
)

const (
	RootUserName    = "root"
	AclAllEntryName = "All" // Saved name for ACL, the same as in Linux

	ExtraCharStr = "@#%^&()'-_+=;:"

	SuperUserGroupName = "Super-users"
	AdminGroupName     = "Admin"
	UsersGroupName     = "Users"

	AmPropertyName   string = "AM"
	AclPropertyName  string = "ACL"
	OtpPropertyName  string = "OTP"
	OcraPropertyName string = "OCRA"
	PwdPropertyName  string = "PWD"
	UmPropertyName   string = "UM"
)

var (
	PropertiesName = map[string]bool{
		AmPropertyName:   true,
		AclPropertyName:  true,
		OtpPropertyName:  true,
		OcraPropertyName: true,
		PwdPropertyName:  true,
		UmPropertyName:   true,
	}
)

type Serializer interface {
	PrintProperties(data interface{}) string
	AddToStorage(prefix string, data interface{}, storage *ss.SecureStorage) error
	ReadFromStorage(prefix string, storage *ss.SecureStorage) (interface{}, error)
	IsEqualProperties(d1 interface{}, d2 interface{}) bool
}

type SerializersMap map[string]Serializer

var Serializers = make(SerializersMap)
