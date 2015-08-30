package entityManagement

import (
	"fmt"

	am "ibm-security-innovation/libsecurity-go/accounts"
	// "ibm-security-innovation/libsecurity-go/acl"
	stc "ibm-security-innovation/libsecurity-go/defs"
	"ibm-security-innovation/libsecurity-go/ocra"
	"ibm-security-innovation/libsecurity-go/otp"
	"ibm-security-innovation/libsecurity-go/password"
)

func GenerateUserData(el *EntityManager, usersName []string, secret []byte, salt []byte) {
	el.AddUser(usersName[0])
	amData, _ := am.NewUserAm(am.SuperUserPermission, secret, salt, false)
	el.AddPropertyToEntity(usersName[0], stc.AmPropertyName, amData)
	otpData, _ := otp.NewSimpleOtpUser(secret, false)
	el.AddPropertyToEntity(usersName[0], stc.OtpPropertyName, otpData)
	pwdData, _ := password.NewUserPwd(secret, salt, false)
	el.AddPropertyToEntity(usersName[0], stc.PwdPropertyName, pwdData)
	ocraData, _ := ocra.NewOcraUser([]byte("ABCD1234"), "OCRA-1:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256")
	el.AddPropertyToEntity(usersName[0], stc.OcraPropertyName, ocraData)

	el.AddUser(usersName[1])
	el.AddPropertyToEntity(usersName[1], stc.OtpPropertyName, otpData)
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
