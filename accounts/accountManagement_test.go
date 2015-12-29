package accounts

import (
	"io/ioutil"
	"testing"
	"time"

	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	"github.com/ibm-security-innovation/libsecurity-go/password"
)

const ()

var (
	defaultUserName = "User1"
	defaultPassword []byte
	defaultSalt     = []byte("salt123")
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)
	defaultPassword = []byte(password.GenerateNewValidPassword())
}

// Test that a new user AM is generated only when all the parameters are valid
func Test_addValidAM(t *testing.T) {
	usersName := []string{defaultUserName, ""}
	privilege := make(map[string]interface{})
	for k, v := range usersPrivilege {
		privilege[k] = v
	}
	privilege["undef"] = ""
	userPwd, _ := password.NewUserPwd(defaultPassword, defaultSalt, true)
	pwd := ""
	for _, userName := range usersName {
		for p := range privilege {
			for i := 0; i < password.MaxPasswordLength; i++ {
				ok := len(userName) > 0 &&
					IsValidPrivilege(p) == nil &&
					userPwd.IsNewPwdValid([]byte(pwd), false) == nil
				_, err := NewUserAm(p, []byte(pwd), defaultSalt, false)
				if ok == false && err == nil {
					t.Errorf("Test fail: Successfully generated new AM with invalid parameters: user name '%v' (%v), privilege '%v' (%v) password '%v' (%v)",
						userName, len(userName) != 0, p, IsValidPrivilege(p), pwd, userPwd.IsNewPwdValid([]byte(pwd), false))
					t.FailNow()
				} else if ok == true && err != nil {
					t.Errorf("Test fail: Error while generated new AM with valid parameters: user name '%v' (%v), privilege '%v' (%v) password '%v' (%v), error: %v",
						userName, len(userName) != 0, p, IsValidPrivilege(p), pwd, userPwd.IsNewPwdValid([]byte(pwd), false), err)
					t.FailNow()
				}
				pwd += "a"
			}
		}
	}
}

// Test that only valid previlege and password can be updated
func Test_updateAM(t *testing.T) {
	privilege := make(map[string]interface{})
	for k, v := range usersPrivilege {
		privilege[k] = v
	}
	privilege["undef"] = ""
	userPwd, _ := password.NewUserPwd(defaultPassword, defaultSalt, true)
	userAm, _ := NewUserAm(SuperUserPermission, defaultPassword, defaultSalt, true)
	pwd := ""
	for p := range privilege {
		for i := 0; i < password.MaxPasswordLength; i++ {
			pOk := IsValidPrivilege(p)
			pwdOk := userPwd.IsNewPwdValid([]byte(pwd), false)
			ok := pOk == nil && pwdOk == nil
			updatePOk := userAm.UpdateUserPrivilege(p)
			updatePwdOk := userAm.UpdateUserPwd(defaultUserName, userAm.Pwd.Password, []byte(pwd), false)
			updateOk := updatePOk == nil && updatePwdOk == nil
			if ok == false && updateOk == true {
				t.Errorf("Test fail: Successfully updated user AM with invalid parameters: privilege '%v' (%v) password '%v' (%v)",
					p, pOk, pwd, pwdOk)
				t.FailNow()
			} else if ok == true && updateOk == false {
				t.Errorf("Test fail: Error while updating user AM with valid parameters: privilege '%v' (%v) password '%v' (%v), error: update privilege: %v, update password %v",
					p, pOk, pwd, pwdOk, updatePOk, updatePwdOk)
				t.FailNow()
			}
			pwd += "a"
		}
	}
}

// Test that only equal AM returns true
func Test_equalAM(t *testing.T) {
	pwd := []string{string(defaultPassword), string(defaultPassword) + "a"}
	userAm, _ := NewUserAm(SuperUserPermission, defaultPassword, defaultSalt, true)
	userAm1, _ := NewUserAm(SuperUserPermission, defaultPassword, defaultSalt, true)

	for p := range usersPrivilege {
		userAm1.UpdateUserPrivilege(p)
		for _, pass := range pwd {
			userAm1.UpdateUserPwd(defaultUserName, userAm.Pwd.Password, []byte(pass), false)
			for exp := 0; exp < 2; exp++ {
				if exp > 0 {
					userAm1.Pwd.Expiration = time.Now().Add(time.Duration(100*24) * time.Hour)
				} else {
					userAm1.Pwd.Expiration = userAm.Pwd.Expiration
				}
				equal := userAm.Privilege == userAm1.Privilege &&
					string(userAm.Pwd.Password) == string(userAm1.Pwd.Password)
				if userAm.IsEqual(userAm1, false) == true && equal == false {
					t.Errorf("Test fail: Unequal AM found equal with withExpiration == false: UserAm: '%v'\nuserAm1 '%v'", userAm, userAm1)
				} else if userAm.IsEqual(userAm1, true) == true && (equal == false || exp > 0) {
					t.Errorf("Test fail: Unequal AM found equal with withExpiration == true: UserAm: '%v'\nuserAm1 '%v'", userAm, userAm1)
				}
				if userAm.IsEqual(userAm1, false) == false && equal == true {
					t.Errorf("Test fail: Equal AM found unequal with withExpiration == false: UserAm: '%v'\nuserAm1 '%v'", userAm, userAm1)
				} else if userAm.IsEqual(userAm1, true) == false && (equal == true && exp == 0) {
					t.Errorf("Test fail: Equal AM found unequal with withExpiration == true: UserAm: '%v'\nuserAm1 '%v'", userAm, userAm1)
				}
			}
		}
	}
}

// Test that the same password returns true
func Test_IsPasswordMatch(t *testing.T) {
	pwd := []string{string(defaultPassword), string(defaultPassword) + "a", ""}
	userAm, _ := NewUserAm(SuperUserPermission, defaultPassword, defaultSalt, true)

	for _, pass := range pwd {
		err := userAm.IsPasswordMatch([]byte(pass))
		if err == nil && pass != string(defaultPassword) {
			t.Errorf("Test fail: curent password '%v' matched wrong password '%v'", string(defaultPassword), pass)
		}
		if err != nil && pass == string(defaultPassword) {
			t.Errorf("Test fail: The same password '%v' wasn't matched '%v', error %v", string(defaultPassword), pass, err)
		}
	}
}
