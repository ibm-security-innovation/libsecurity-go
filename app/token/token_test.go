package token

import (
	//	"fmt"
	"testing"

	am "github.com/ibm-security-innovation/libsecurity-go/accounts"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
)

const (
	defaultUserName = "User1"
	defaultIP       = "1.2.3.4"

	privateKeyFilePath = "./dist/key.private"
)

var ()

func init() {
}

// Verify that only the same tokens are equal
func Test_GenerateToken(t *testing.T) {
	usersName := []string{defaultUserName, defaultUserName + "a", ""}
	ipsStr := []string{defaultIP, defaultIP + "1", ""}
	usersPrivilege := am.GetUsersPrivilege()
	signKey, verifyKey := SetupAToken(privateKeyFilePath)

	for _, name := range usersName {
		for _, ip := range ipsStr {
			for p := range usersPrivilege {
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
	groupsName := []string{defs.UsersGroupName, defs.AdminGroupName, defs.SuperUserGroupName}
	usersName := []string{"user", "admin", "super"}
	permissions := []string{am.UserPermission, am.AdminPermission, am.SuperUserPermission}

	signKey, verifyKey := SetupAToken(privateKeyFilePath)

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
		token1, _ := GenerateToken(name, permissions[i], defaultIP, signKey)
		for j := range usersName {
			ok, err := IsPrivilegeOk(token1, permissions[j], defaultIP, verifyKey)
			if j > i && ok == true {
				t.Errorf("Test fail: Is privilege returns %v but the token privilege is '%v' and the check was for '%v', error %v", ok, usersName[i], permissions[j], err)
			} else if j <= i && ok == false {
				t.Errorf("Test fail: Is privilege returns %v but the token privilege is '%v' and the check was for '%v', error %v", ok, usersName[i], permissions[j], err)
			}
		}
	}
	for _, name1 := range usersName {
		token1, _ := GenerateToken(name1, name1, defaultIP, signKey)
		for _, name2 := range usersName {
			ok, _ := IsItTheSameUser(token1, name2, defaultIP, verifyKey)
			if name1 != name2 && ok == true {
				t.Errorf("Test fail: IsItTheSameUser returns true but the names are different: '%v', '%v'", name1, name2)
			} else if name1 == name2 && ok == false {
				t.Errorf("Test fail: IsItTheSameUser returns false but the names are the same: '%v', '%v'", name1, name2)
			}
		}
	}
}
