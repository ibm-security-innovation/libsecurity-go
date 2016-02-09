package libsecurityRestful

import (
	"testing"

	am "github.com/ibm-security-innovation/libsecurity-go/accounts"
	"github.com/ibm-security-innovation/libsecurity-go/acl"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	"github.com/ibm-security-innovation/libsecurity-go/ocra"
	"github.com/ibm-security-innovation/libsecurity-go/otp"
	"github.com/ibm-security-innovation/libsecurity-go/password"
)

const ()

var (
	St *LibsecurityRestful

	secret = []byte("ABCDEFGH12345678")
	salt   = []byte("Salt")
)

func init() {
	St = NewLibsecurityRestful()
}

// Verify that get property from undefined user returns an error
// Verify that get property from user before setting the OTP property, returns an error
// Verify that get property from user after setting the property returns the same property as was setted to the user
// Verify that get property from user after removing the OTP property returns an error
// Verify that get property from user after readding the OTP property returns OK
// Verify that get property from user that was removed after OTP property was set, returns an error
// Verify that Add a property to user, remove the user, generate a new user with the same name and try to get the property returns an error
func testAddCheckRemoveUserProperty(t *testing.T, propertyName string, moduleData interface{}) {
	name := "name1"
	usersList := en.New()
	_, err := usersList.GetPropertyAttachedToEntity(name, propertyName)
	if err == nil {
		t.Errorf("Test fail, Recived module '%v' of undefined user '%v'", propertyName, name)
	}

	usersList.AddResource(name)
	_, err = usersList.GetPropertyAttachedToEntity(name, propertyName)
	if err == nil {
		t.Errorf("Test fail, Recived module '%v' of not registered yet module for user '%v'", propertyName, name)
	}

	usersList.AddPropertyToEntity(name, propertyName, moduleData)
	tmp, err := usersList.GetPropertyAttachedToEntity(name, propertyName)
	if err != nil {
		t.Errorf("Test fail, Error while feteching module '%v' from user '%v', error: %v", propertyName, name, err)
	}
	if moduleData != tmp {
		t.Errorf("Test fail, Added '%v' property '%v' is not equal to the fetched one '%v'", propertyName, moduleData, tmp)
	}

	usersList.RemovePropertyFromEntity(name, propertyName)
	_, err = usersList.GetPropertyAttachedToEntity(name, propertyName)
	if err == nil {
		t.Errorf("Test fail, Removed module '%v' from user '%v' was successfully fetched", propertyName, name)
	}

	usersList.AddPropertyToEntity(name, propertyName, moduleData)
	_, err = usersList.GetPropertyAttachedToEntity(name, propertyName)
	if err != nil {
		t.Errorf("Test fail, Error while feteching module '%v' from user '%v', error: %v", propertyName, name, err)
	}

	usersList.RemoveResource(name)
	_, err = usersList.GetPropertyAttachedToEntity(name, propertyName)
	if err == nil {
		t.Errorf("Test fail, Module '%v' of removed user '%v' was successfully fetched", propertyName, name)
	}
	err = usersList.AddPropertyToEntity(name, propertyName, moduleData)
	if err == nil {
		t.Errorf("Test fail, Atteched module '%v' to removed user '%v'", propertyName, name)
	}
	usersList.AddResource(name)
	_, err = usersList.GetPropertyAttachedToEntity(name, propertyName)
	if err == nil {
		t.Errorf("Test fail, Module '%v' was fetched before atttached to the user '%v'", propertyName, name)
	}
}

func Test_AddCheckRemoveOtpUserProperty(t *testing.T) {
	moduleData, _ := otp.NewSimpleOtpUser(secret, false)

	testAddCheckRemoveUserProperty(t, defs.OtpPropertyName, moduleData)
}

func Test_AddCheckRemovePwdUserProperty(t *testing.T) {
	moduleData, _ := password.NewUserPwd(secret, salt, false)

	testAddCheckRemoveUserProperty(t, defs.PwdPropertyName, moduleData)
}

func Test_AddCheckRemoveOcraUserProperty(t *testing.T) {
	moduleData, _ := ocra.NewOcraUser([]byte("12345678"), "OCRA-1:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256")

	testAddCheckRemoveUserProperty(t, defs.OcraPropertyName, moduleData)
}

func Test_AddCheckRemoveAMUserProperty(t *testing.T) {
	moduleData, _ := am.NewUserAm(am.SuperUserPermission, secret, salt, false)

	testAddCheckRemoveUserProperty(t, defs.AmPropertyName, moduleData)
}

func Test_AddCheckRemoveACLUserProperty(t *testing.T) {
	moduleData := acl.NewACL()

	testAddCheckRemoveUserProperty(t, defs.AclPropertyName, moduleData)
}
