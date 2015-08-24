package token

import (
	//	"fmt"
	"testing"

	am "ibm-security-innovation/libsecurity-go/accounts"
	stc "ibm-security-innovation/libsecurity-go/defs"
)

const (
	defaultUserName = "User1"
	defaultIp       = "1.2.3.4"

	privateKeyFilePath = "./dist/key.private"
)

var ()

func init() {
}

// Verify that only the same tokens are equal
func Test_GenerateToken(t *testing.T) {
	usersName := []string{defaultUserName, defaultUserName + "a", ""}
	ipsStr := []string{defaultIp, defaultIp + "1", ""}
	usersPrivilege := am.GetUsersPrivilege()
	signKey, verifyKey := TokenSetUp(privateKeyFilePath)

	for _, name := range usersName {
		for _, ip := range ipsStr {
			for p, _ := range usersPrivilege {
				token1, _ := GenerateToken(name, p, ip, signKey)
				data, err := ParseToken(token1, ip, verifyKey)
				if err != nil || data.UserName != name || data.Privilege != p {
					t.Errorf("Test fail: the parsed token != generated token, error: %v", err)
				}
				_, err = ParseToken(token1, ip+"1", verifyKey)
				if err == nil {
					t.Errorf("Test fail: return successful from parsed token but the IPs are different")
				}
			}
		}
	}
}

// Verify that only user with the relevant privilege can run the operation
// Verify that the IsTheSameUser return the expected value
func Test_CheckPrivilegeAndSameUser(t *testing.T) {
	groupsName := []string{stc.UsersGroupName, stc.AdminGroupName, stc.SuperUserGroupName}
	usersName := []string{"user", "admin", "super"}
	permissions := []string{am.UserPermission, am.AdminPermission, am.SuperUserPermission}

	signKey, verifyKey := TokenSetUp(privateKeyFilePath)

	for _, name := range usersName {
		usersList.AddUser(name)
	}
	for i, name := range groupsName {
		usersList.AddGroup(name) // to be on the safe side
		for j := i; j < len(usersName); j++ {
			usersList.AddUserToGroup(name, usersName[j])
		}
	}
	for i, name := range usersName {
		token1, _ := GenerateToken(name, permissions[i], defaultIp, signKey)
		for j, _ := range usersName {
			ok, err := IsPrivilegeOk(token1, permissions[j], defaultIp, verifyKey)
			if j > i && ok == true {
				t.Errorf("Test fail: Is privilege returns %v but the token privilege is '%v' and the check was for '%v', error %v", ok, usersName[i], permissions[j], err)
			} else if j <= i && ok == false {
				t.Errorf("Test fail: Is privilege returns %v but the token privilege is '%v' and the check was for '%v', error %v", ok, usersName[i], permissions[j], err)
			}
		}
	}
	for _, name1 := range usersName {
		token1, _ := GenerateToken(name1, name1, defaultIp, signKey)
		for _, name2 := range usersName {
			ok, _ := IsItTheSameUser(token1, name2, defaultIp, verifyKey)
			if name1 != name2 && ok == true {
				t.Errorf("Test fail: IsItTheSameUser returns true but the names are different: '%v', '%v'", name1, name2)
			} else if name1 == name2 && ok == false {
				t.Errorf("Test fail: IsItTheSameUser returns false but the names are the same: '%v', '%v'", name1, name2)
			}
		}
	}
}
