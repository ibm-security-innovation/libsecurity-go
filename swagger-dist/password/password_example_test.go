package password_test

import (
	"fmt"

	"ibm-security-innovation/libsecurity-go/password"
	"ibm-security-innovation/libsecurity-go/salt"
)

var (
	minPasswordLength = 1
	maxPasswordLength = 255
)

// Example of how to use the password.
// 1. Create a new password.
// 2. Verify that the initial password is set correctly
// 3. Change the user's password
// 4. Verify that the old password is not valid anymore
// 5. Verify that the new password is valid
// 6. Verify that the old password can't be used any more
//     (at least not as long as it remains in the old passwords list)
func ExampleUserPwd() {
	id := "User-1"
	pwd := []byte("a1b2c3d")
	saltStr, _ := salt.GetRandomSalt(8)

	userPwd, _ := password.NewUserPwd(pwd, saltStr)
	tPwd, _ := salt.GenerateSaltedPassword(pwd, minPasswordLength, maxPasswordLength, saltStr, -1)
	newPwd := password.GetHashedPwd(tPwd)
	err := userPwd.IsPasswordMatch(newPwd)
	if err != nil {
		fmt.Println("Ravid: error", err)
	}
	userNewPwd := []byte(string(pwd) + "a")
	newPwd, err = userPwd.UpdatePassword(userPwd.Password, userNewPwd)
	if err != nil {
		fmt.Printf("Password update for user %v to new password '%v' (%v) failed, error: %v\n", id, newPwd, string(userNewPwd), err)
	} else {
		fmt.Printf("User: '%v', updated password to '%v' (%v)\n", id, newPwd, string(userNewPwd))
	}
	err = userPwd.IsPasswordMatch(newPwd)
	if err != nil {
		fmt.Printf("Check of the new password: '%v' (%v) for user: %v failed, error: %v\n", newPwd, string(userNewPwd), id, err)
	} else {
		fmt.Printf("User: '%v', new password '%v' (%v) verified successfuly\n", id, newPwd, string(userNewPwd))
	}
	err = userPwd.IsPasswordMatch(pwd)
	if err == nil {
		fmt.Printf("Error: Old password: '%v' (%v) for user: %v accepted\n", pwd, string(pwd), id)
	} else {
		fmt.Printf("User: '%v', Note that the old password '%v' (%v) can't be used anymore\n", id, pwd, string(pwd))
	}
	newPwd, err = userPwd.UpdatePassword(userPwd.Password, pwd)
	if err == nil {
		fmt.Printf("Error: Password '%v' (typed password %v) for user %v was alredy used\n", newPwd, string(pwd), id)
	} else {
		fmt.Printf("Entity: '%v', Note that the old password (entered password) %v as it was already used\n", id, string(pwd))
	}
}

// Example of how to use the reset password function:
// This function resets the current password,
// selects a new password with short expiration time
// and lets the user use it exactly once
func ExampleUserPwd_ResetPasword() {
	id := "User1"
	pwd := []byte("a1b2c3d")

	saltStr, _ := salt.GetRandomSalt(10)
	userPwd, _ := password.NewUserPwd(pwd, saltStr)
	tmpPwd, _ := userPwd.ResetPasword()
	tPwd, _ := salt.GenerateSaltedPassword(tmpPwd, 1, 100, saltStr, -1)
	newPwd := password.GetHashedPwd(tPwd)
	err := userPwd.IsPasswordMatch(newPwd)
	if err != nil {
		fmt.Printf("Check of newly generated password: '%v' for user: %v failed, error: %v\n", newPwd, id, err)
	} else {
		fmt.Printf("Entity %v, after reseting password '%v' verified successfuly\n", id, newPwd)
	}
	err = userPwd.IsPasswordMatch(newPwd)
	if err == nil {
		fmt.Printf("Error: Newly generated password: '%v' could be used only once\n", newPwd)
	} else {
		fmt.Printf("Newly generated password: '%v', for entity: %v, can only be used once\n", newPwd, id)
	}
}
