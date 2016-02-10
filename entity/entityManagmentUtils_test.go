package entityManagement

import (
	"fmt"

	am "github.com/ibm-security-innovation/libsecurity-go/accounts"
	// "github.com/ibm-security-innovation/libsecurity-go/acl"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	"github.com/ibm-security-innovation/libsecurity-go/ocra"
	"github.com/ibm-security-innovation/libsecurity-go/otp"
	"github.com/ibm-security-innovation/libsecurity-go/password"
)

func GenerateUserData(el *EntityManager, usersName []string, secret []byte, salt []byte) {
	el.AddUser(usersName[0])
	el.AddResource("r"+usersName[0])
	amData, _ := am.NewUserAm(am.SuperUserPermission, secret, salt, false)
	el.AddPropertyToEntity(usersName[0], defs.AmPropertyName, amData)
	otpData, _ := otp.NewSimpleOtpUser(secret, false)
	el.AddPropertyToEntity(usersName[0], defs.OtpPropertyName, otpData)
	pwdData, _ := password.NewUserPwd(secret, salt, false)
	el.AddPropertyToEntity(usersName[0], defs.PwdPropertyName, pwdData)
	ocraData, _ := ocra.NewOcraUser([]byte("ABCD1234"), "OCRA-1:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256")
	el.AddPropertyToEntity(usersName[0], defs.OcraPropertyName, ocraData)

	el.AddUser(usersName[1])
	el.AddPropertyToEntity(usersName[1], defs.OtpPropertyName, otpData)
}

func GenerateGroupList(el *EntityManager, usersName []string) {
	for i := 0; i < 3; i++ {
		groupName := fmt.Sprintf("group-%d", i+1)
		el.AddGroup(groupName)
		for j := 0; j < i; j++ {
			el.AddUserToGroup(groupName, usersName[j])
		}
	}
}
