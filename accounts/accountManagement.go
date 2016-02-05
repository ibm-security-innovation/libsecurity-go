// Package accounts :
// The Account Management package handles user privileges and password management.
//
// The data structure is:
// 	- Entity's privilege (Super user, Admin or User)
// 	- Password related information and handling methods including:
//	- The current passwordpassw
//	- The password's expiration time
//	- Old passwords that should be avoided. If there is an attempt to reused an old the user is flagged.
//	- Error counter: counts the number of consecutive unsuccessful authentication attempts
//	- Is it a 'temporary password' (after password reset)
package accounts

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sync"
	"time"

	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	"github.com/ibm-security-innovation/libsecurity-go/password"
	"github.com/ibm-security-innovation/libsecurity-go/salt"
	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

const (
	// SuperUserPermission : string that defines the super user permission
	SuperUserPermission = "Super-user"
	// AdminPermission : string that defines the administrator permission
	AdminPermission = "Admin"
	// UserPermission : string that defines the user permission
	UserPermission = "User"

	rootPwdExpirationDays = 3550
	pwdExpirationDays     = 90
)

var (
	usersPrivilege UsersPrivilege

	lock sync.Mutex
)

// UsersPrivilege : hash structure that defines the allowed privileges
type UsersPrivilege map[string]interface{}

// AmUserInfo : structure that defines the data atached to the user: password and privilege
type AmUserInfo struct {
	Pwd       password.UserPwd
	Privilege string
}

// Serializer : virtual set of functions that must be implemented by each module
type Serializer struct{}

func (u AmUserInfo) String() string {
	return fmt.Sprintf("Privilege: '%v', Password: %v", u.Privilege, u.Pwd)
}

func init() {
	usersPrivilege = make(UsersPrivilege)
	usersPrivilege[UserPermission] = ""
	usersPrivilege[SuperUserPermission] = ""
	usersPrivilege[AdminPermission] = ""

	defs.Serializers[defs.AmPropertyName] = &Serializer{}
}

func (u *AmUserInfo) setLogger(severity string, fileName string) {
	logger.Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
}

// NewUserAm : Generate and return a new Account Management object using the given priviledge, password and salt (in case they are valid)
func NewUserAm(privilege string, pass []byte, saltData []byte, checkPwdStrength bool) (*AmUserInfo, error) {
	err := IsValidPrivilege(privilege)
	if err != nil {
		return nil, err
	}
	// was userPwd := password.UserPwd{Password: pass, Expiration: getPwdExpiration(id), Salt: saltData}
	userPwd, err := password.NewUserPwd(pass, saltData, checkPwdStrength)
	if err != nil {
		return nil, err
	}
	return &AmUserInfo{Pwd: *userPwd, Privilege: privilege}, nil
}

// IsValidPrivilege : Verify that the privilage is a member of the set of valid options
func IsValidPrivilege(privilege string) error {
	_, exist := usersPrivilege[privilege]
	if !exist {
		return fmt.Errorf("the user privilege '%v' is not legal, it must be one of %v",
			privilege, usersPrivilege)
	}
	return nil
}

// GetUsersPrivilege : The predefind set of valid privilege
func GetUsersPrivilege() UsersPrivilege {
	return usersPrivilege
}

// Return the time expiration of the AM password, root time expiration is different
// than all other users time expiration
func getPwdExpiration(id string) time.Time {
	if id != defs.RootUserName {
		return time.Now().Add(time.Hour * 24 * pwdExpirationDays)
	}
	// root password dosn't have expiration limit
	return time.Now().Add(time.Hour * 24 * rootPwdExpirationDays)
}

// UpdateUserPrivilege : Set the AM property privilege to the given value (only for valid privileges)
func (u *AmUserInfo) UpdateUserPrivilege(privilege string) error {
	err := IsValidPrivilege(privilege)
	if err != nil {
		return err
	}
	u.Privilege = privilege
	return nil
}

// UpdateUserPwd : Update the AM property password to the given password and set the expiration time
// The password will be updated only if the new password is valid and the curent password matches the given one
func (u *AmUserInfo) UpdateUserPwd(userName string, currentPwd []byte, pwd []byte, checkPwdStrength bool) error {
	newPwd, err := u.Pwd.UpdatePassword(currentPwd, pwd, checkPwdStrength)
	if err != nil {
		return err
	}
	u.Pwd.Password = newPwd
	u.Pwd.Expiration = getPwdExpiration(userName)
	return nil
}

// ResetUserPwd : Update the AM property password to a random password and set the expiration time
// The password will be updated only if the new password is valid and the curent password matches the given one
func (u *AmUserInfo) ResetUserPwd(userName string) ([]byte, error) {
	newPwd, err := u.Pwd.ResetPassword()
	if err != nil {
		return nil, err
	}
	return newPwd, nil
}

// PasswordErrorThrotling : throttle the session in case of wrong password,
//	the delay is the sum of a constant value: throttleMiliSec plus a random between 1 and randomThrottleMiliSec
//	the random is to be counterpart to timing attacks
func PasswordErrorThrotling(throttleMiliSec int64, randomThrottleMiliSec int64) {
	defs.TimingAttackSleep(throttleMiliSec, randomThrottleMiliSec)
}

// IsPasswordMatch : Check if a given password matches the curent password
// Note that the passwords are stored after hashing and not as clear text
// If the passwords don't match, a 1 second delay will be used before the
// next attempt, in order to prevent brute force entry attempts
func (u *AmUserInfo) IsPasswordMatch(pwd []byte) error {
	return u.IsPasswordMatchHandler(pwd, defs.PasswordThrottlingMiliSec, defs.ThrottleMaxRandomMiliSec)
}

// IsPasswordMatchHandler : use IsPasswordMatch with throttling parameters other than the default ones, for testing purposes
func (u *AmUserInfo) IsPasswordMatchHandler(pwd []byte, throttleMiliSec int64, randomThrottleMiliSec int64) error {
	saltedPwd, _ := salt.GenerateSaltedPassword([]byte(pwd), password.MinPasswordLength, password.MaxPasswordLength, u.Pwd.Salt, -1)
	tPwd := password.GetHashedPwd(saltedPwd)
	err := u.Pwd.IsPasswordMatch(tPwd)
	// on error throttle for 1 second, reset the error counter
	if err != nil {
		PasswordErrorThrotling(throttleMiliSec, randomThrottleMiliSec)
		// u.Pwd.ErrorsCounter = 0 // the throttling is enougth
		return err
	}
	return nil
}

// IsEqual : Comapre 2 AM properties, the comparisson may be set not to compare the expiration time
func (u AmUserInfo) IsEqual(u2 *AmUserInfo, withExpiration bool) bool {
	if u2 == nil {
		return false
	}
	p2 := u2.Pwd
	if withExpiration == false {
		p2.Expiration = u.Pwd.Expiration
	}
	if u2.Privilege != u.Privilege || reflect.DeepEqual(p2, u.Pwd) == false {
		return false
	}
	return true
}

// All the properties must implement a set of functions:
// PrintProperties, IsEqualProperties, AddToStorage, ReadFromStorage

// PrintProperties : Print the AM property data
func (s Serializer) PrintProperties(data interface{}) string {
	d, ok := data.(*AmUserInfo)
	if ok == false {
		return "can't print the Account management property it is not in the right type"
	}
	return d.String()
}

// IsEqualProperties : Compare 2 AM properties
func (s Serializer) IsEqualProperties(da1 interface{}, da2 interface{}) bool {
	d1, ok1 := da1.(*AmUserInfo)
	d2, ok2 := da2.(*AmUserInfo)
	if ok1 == false || ok2 == false {
		return false
	}
	return d1.IsEqual(d2, true)
}

// AddToStorage : Add the AM property information to the secure_storage
func (s Serializer) AddToStorage(prefix string, data interface{}, storage *ss.SecureStorage) error {
	lock.Lock()
	defer lock.Unlock()

	d, ok := data.(*AmUserInfo)
	if ok == false {
		return fmt.Errorf("can't store the Account management property, it has an illegal type")
	}
	if storage == nil {
		return fmt.Errorf("can't add AM property to storage, storage is nil")
	}
	value, _ := json.Marshal(d)
	err := storage.AddItem(prefix, string(value))
	if err != nil {
		return err
	}
	return nil
}

// ReadFromStorage : Return the entity AM data read from the secure storage
func (s Serializer) ReadFromStorage(key string, storage *ss.SecureStorage) (interface{}, error) {
	var user AmUserInfo

	if storage == nil {
		return nil, fmt.Errorf("can't read AM property from storage, storage is nil")
	}
	value, exist := storage.Data[key]
	if exist == false {
		return nil, fmt.Errorf("key '%v' was not found", key)
	}
	err := json.Unmarshal([]byte(value), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
