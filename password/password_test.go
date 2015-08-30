package password

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"ibm-security-innovation/libsecurity-go/salt"
)

var (
	defaultPassword []byte
	defaultSaltStr  = []byte("abcd")
)

func init() {
	defaultPassword = []byte(GenerateNewValidPassword())
}

func checkValidPasswordLen(t *testing.T, user *UserPwd) {
	pwd := ""
	for i := 0; i < MaxPasswordLength+2; i++ {
		err := isPwdLengthValid([]byte(pwd))
		if err != nil && i >= MinPasswordLength && i <= MaxPasswordLength {
			t.Errorf("Test fail: Legal password:'%v', length: %v, was not excepted, error: %v", pwd, len(pwd), err)
		}
		if err == nil && (i < MinPasswordLength || i > MaxPasswordLength) {
			t.Errorf("Test fail: Legal password: '%v', length: %v, was not excepted", pwd, len(pwd))
		}
		pwd += "a"
	}
}

// Fill the oldPasswords list with passwords and verify that
// random selected passwords are treated as expected
func checkUnusabledOldPasswords(t *testing.T, user *UserPwd) {
	unused := 1
	for i := 0; i < defaultNumberOfOldPasswords-unused; i++ {
		user.OldPasswords[i] = GetHashedPwd([]byte(string(defaultPassword) + fmt.Sprintf("%d", i)))
	}
	buf := make([]byte, 1)
	for i := 0; i < defaultNumberOfOldPasswords*4; i++ {
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			panic(fmt.Errorf("random read failed: %v", err))
		}
		idx := int(buf[0]) % (defaultNumberOfOldPasswords * 2)
		pwd := []byte(string(defaultPassword) + fmt.Sprintf("%d", idx))
		err = user.IsNewPwdValid(pwd, false)
		if err == nil && idx < defaultNumberOfOldPasswords-unused {
			t.Errorf("Test fail: password '%v' was already used, but it was accepted, user data: %v", pwd, user)
			t.FailNow()
		} else if err != nil && idx >= defaultNumberOfOldPasswords-unused {
			t.Errorf("Test fail: user: %v, password '%v' rejected, but it was't used, error: %v", user, pwd, err)
			t.FailNow()
		}
	}
}

// Test that a valid password axcpeted and wrong password is declined
// Valid password must be: with length of at least MinPasswordLength and not more than MaxPasswordLength,
// was not used before in the last defaultNumberOfOldPasswords
func Test_ValidPwd(t *testing.T) {
	user, err := NewUserPwd(defaultPassword, defaultSaltStr, true)
	if err != nil {
		t.Error("Test fail, can't initialized user password structure, error:", err)
		t.FailNow()
	}
	checkValidPasswordLen(t, user)
	checkUnusabledOldPasswords(t, user)
}

// Check if update password is respond as expected: for valid password it accept it
// and add it the previus password to the old passwords list
// and reject the previus password for the next defaultNumberOfOldPasswords passwords updates
func Test_UpdatePwd(t *testing.T) {
	user, err := NewUserPwd(defaultPassword, defaultSaltStr, true)
	if err != nil {
		t.Error("Test fail, can't initialized user password structure, error:", err)
		t.FailNow()
	}
	for i := 0; i < defaultNumberOfOldPasswords*2; i++ {
		pwd := []byte(string(defaultPassword) + fmt.Sprintf("%d", i))
		newPwd, err := user.UpdatePassword(user.Password, pwd, true)
		if err != nil {
			t.Errorf("Test fail: user: %v, password %v, ('%v') rejected, but it was't used, error: %v", user, newPwd, string(pwd), err)
		}
		for j := i; j >= i-defaultNumberOfOldPasswords && j >= 0; j-- {
			pwd := []byte(string(defaultPassword) + fmt.Sprintf("%d", j))
			newPwd, err := user.UpdatePassword(user.Password, pwd, true)
			if err == nil {
				t.Errorf("Test fail: password %v ('%v') was already used, but it was accepted, user data: %v", newPwd, string(pwd), user)
			}
		}
	}
}

// Check that verify password works ok: it return true only if the following requiremnts are OK:
// The password is equal to the current password and the password is not expired
func Test_VerifyPwd(t *testing.T) {
	uPwd, err := NewUserPwd(defaultPassword, defaultSaltStr, true)
	if err != nil {
		t.Error("Test fail, can't initialized user password structure, error:", err)
		t.FailNow()
	}
	tPwd, _ := salt.GenerateSaltedPassword(defaultPassword, MinPasswordLength, MaxPasswordLength, uPwd.Salt, -1)
	pwd := GetHashedPwd(tPwd)
	err = uPwd.IsPasswordMatch(pwd)
	if err != nil {
		t.Errorf("Test fail: password '%v' was not accepted but it is the same as the current password, %v, error: %v", pwd, uPwd, err)
	}
	tPwd, _ = salt.GenerateSaltedPassword([]byte(string(pwd)+"a"), MinPasswordLength, MaxPasswordLength, uPwd.Salt, -1)
	wrongPwd := GetHashedPwd(tPwd)
	err = uPwd.IsPasswordMatch(wrongPwd)
	if err == nil {
		t.Errorf("Test fail: password '%v' was approved but it is different from the current password, %v", wrongPwd, uPwd)
	}
	for i := -2; i < 3; i++ {
		if i == 0 {
			continue
		}
		uPwd.Expiration = time.Now().Add(time.Duration(i) * time.Second)
		err = uPwd.IsPasswordMatch(pwd)
		if err == nil && i <= 0 {
			t.Errorf("Test fail: password was approved but it is not valid (expired, time now %v), %v", time.Now(), uPwd.Expiration)
		} else if err != nil && i > 0 {
			t.Errorf("Test fail: password was not approved but it valid (time now %v), %v", time.Now(), uPwd.Expiration)
		}
	}
}

// Check that one time password can be used exctly once
func Test_UseOfOneTimePwd(t *testing.T) {
	user, err := NewUserPwd(defaultPassword, defaultSaltStr, true)
	if err != nil {
		t.Error("Test fail, can't initialized user password structure, error:", err)
		t.FailNow()
	}
	tPwd, _ := salt.GenerateSaltedPassword(defaultPassword, MinPasswordLength, MaxPasswordLength, user.Salt, -1)
	pwd := GetHashedPwd(tPwd)
	user.SetOneTimePwd(true)
	err = user.IsPasswordMatch(pwd)
	if err != nil {
		t.Errorf("Test fail: password '%v' was not accepted but it is the same as the current password, %v, current time: %v, error: %v", pwd, user, time.Now(), err)
	}
	err = user.IsPasswordMatch(pwd)
	if err == nil {
		t.Errorf("Test fail: password '%v' accepted but it was a one time password, and it was already used, %v, current time: %v", pwd, user, time.Now())
	}
}

// Check that password is blocked after too many atempts
// and will be checked again only after new password setting
// Verify that successful attemt resets the attempts counter
func Test_VerifyPwdBlocked(t *testing.T) {
	wrongPwd := []byte(GenerateNewValidPassword())
	user, err := NewUserPwd(defaultPassword, defaultSaltStr, true)
	if err != nil {
		t.Error("Test fail, can't initialized user password structure, error:", err)
		t.FailNow()
	}
	for i := 0; i < maxPwdAttempts*2; i++ {
		for j := 0; j < i; j++ {
			user.IsPasswordMatch(wrongPwd)
		}
		err = user.IsPasswordMatch(user.Password)
		if err != nil && i < maxPwdAttempts {
			t.Errorf("Test fail: password was blocked after %v attempts, it should be blocked only after %v wrong attempts", i, maxPwdAttempts)
		} else if err == nil && i >= maxPwdAttempts {
			t.Errorf("Test fail: password was not blocked after %v wrong attempts, it should be blocked after %v wrong attempts", i, maxPwdAttempts)
		} else if err != nil && i >= maxPwdAttempts {
			pwd := GenerateNewValidPassword()
			expiration := time.Now().Add(time.Duration(defaultOneTimePwdExpirationMinutes) * time.Second * 60)
			user.updatePasswordHandler(user.Password, pwd, expiration, false, true)
			err = user.IsPasswordMatch(user.Password)
			if err != nil {
				t.Errorf("Test fail: password errorCoounter must be cleared after password set, counter attempts: %v", user.ErrorsCounter)
			}
		}
	}
}

// Verify that the password is OK, after reset password, the old password
// it not OK, the new temporary password is OK only once
// and after password update, the new password is valid
func Test_ResetPassword(t *testing.T) {
	user, _ := NewUserPwd(defaultPassword, defaultSaltStr, true)
	tPwd, _ := salt.GenerateSaltedPassword(defaultPassword, MinPasswordLength, MaxPasswordLength, user.Salt, -1)
	pass := GetHashedPwd(tPwd)
	err := user.IsPasswordMatch(pass)
	if err != nil {
		t.Errorf("Test fail: correct password: '%v', return an error: %v", pass, err)
	}
	tmpPwd, err := user.ResetPasword()
	if err != nil {
		t.Errorf("Test fail: Reset password fail, error: %v", err)
	}
	tPwd, _ = salt.GenerateSaltedPassword(tmpPwd, MinPasswordLength, MaxPasswordLength, user.Salt, -1)
	newPwd := GetHashedPwd(tPwd)
	err = user.IsPasswordMatch(pass)
	if err == nil {
		t.Errorf("Test fail: Old password: '%v' accepted", pass)
	}
	err = user.IsPasswordMatch(newPwd)
	if err != nil {
		t.Errorf("Test fail: The new automatic generated password: '%v' was not accepted, error: %v", newPwd, err)
	}
	err = user.IsPasswordMatch(pass)
	if err == nil {
		t.Errorf("Test fail: The one time pwd: '%v' accepted twice", newPwd)
	}
	for i := 0; i < 3; i++ {
		pass = []byte(string(pass) + "a1^A")
		expiration := time.Now().Add(time.Duration(defaultOneTimePwdExpirationMinutes) * time.Second * 60)
		newPwd, err := user.UpdatePasswordAfterReset(user.Password, pass, expiration)
		if err != nil {
			t.Errorf("Test fail: can't use the new password: '%v' (%v), return an error: %v", pass, string(pass), err)
		} else {
			err := user.IsPasswordMatch(newPwd)
			if err != nil {
				t.Errorf("Test fail: correct password: '%v' (%v), return an error: %v", newPwd, string(pass), err)
			}
		}
	}
}

func Test_GenerateRandomPassword(t *testing.T) {
	vec := make(map[string]bool)
	itterations := 100000
	dupPassLen := 100
	var dupPass [100]string

	cnt := 0
	for i := 0; i < itterations; i++ {
		pass := string(GenerateNewValidPassword())
		_, exist := vec[pass]
		if exist {
			if cnt < dupPassLen {
				dupPass[cnt] = pass
				cnt += 1
			}
		} else {
			vec[pass] = true
		}
		err := CheckPasswordStrength(pass)
		if err != nil {
			t.Errorf("Test fail: The generated password '%v' dose not match the password strength test, error %v", pass, err)
			t.FailNow()
		}
	}
	if cnt > 1 {
		t.Error("Test fail: Too many random passwords:", cnt, "were the same, when choosing", itterations, "random passwords", dupPass)
	}
}
