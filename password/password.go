// The password package provides implementation of Password services: Encryption, salting, reset, time expiration and throttling.
//
// The password package handles the following:
//	- Generating a new (salted) password,
//	- Checking if a given password matches a given user's password
//	- Updating a user's password
//	- Resetting a password to a password that can only be used once within a predifined window of time
//
// Passwords have the following properties:
//	- The current password
//	- The password's expiration time
//	- Old passwords that should be avoided. If there is an attempt to reused an old the user is flagged.
//	- Error counter: counts the number of consecutive unsuccessful authentication attempts
//	- Is it a 'one time password' (after password reset)
//
// Note that users are also flagged if they attempt to use a one-time-passwords more than once
package password

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

	stc "ibm-security-innovation/libsecurity-go/defs"
	"ibm-security-innovation/libsecurity-go/salt"
	ss "ibm-security-innovation/libsecurity-go/storage"
)

// Note: Secure storage and the strength of the password are not handled by this package
const (
	defaultPasswordLen                 = 10
	defaultExpirationDurationDays      = 90
	defaultNumberOfOldPasswords        = 5
	defaultOneTimePwd                  = false
	defaultPwdAttempts                 = 10
	defaultOneTimePwdExpirationMinutes = 60

	MinPasswordLength = 8
	MaxPasswordLength = 256

	extraCharStr  = "@#%^&()'-_+=;:"
	digitStr      = "0123456789"
	minRegularCnt = 4
	minUpperCase  = 1
	minLowerCase  = 1
	minDigits     = 2
	minExtraChars = 1
)

var (
	maxPwdAttempts = defaultPwdAttempts

	pLock  sync.Mutex
	p1Lock sync.Mutex
)

type UserPwd struct {
	Password      []byte
	Salt          []byte
	Expiration    time.Time
	ErrorsCounter int
	OneTimePwd    bool // must be replaced after the first use
	OldPasswords  [defaultNumberOfOldPasswords][]byte
}

func (u UserPwd) String() string {
	return fmt.Sprintf("Password: %v, Salt: %v, Expiration: %v, Errors counter: %v, One time password: %v, Old passwords: %v",
		u.Password, u.Salt, u.Expiration, u.ErrorsCounter, u.OneTimePwd, u.OldPasswords)
}

type Serializer struct{}

func init() {
	stc.Serializers[stc.PwdPropertyName] = &Serializer{}
}

// Verify that the password length is in the defined range
func isPwdLengthValid(pwd []byte) error {
	pLen := len(pwd)
	if pLen < MinPasswordLength || pLen > MaxPasswordLength {
		return fmt.Errorf("password length %v is not in the allowed range %v-%v", pLen, MinPasswordLength, MaxPasswordLength)
	}
	return nil
}

// Verify that the password is legal: its length is OK and it wasn't recently used
func (u UserPwd) IsNewPwdValid(pwd []byte) error {
	err := isPwdLengthValid(pwd)
	if err != nil {
		return err
	}
	newPwd := GetHashedPwd(pwd)
	if compareHashedPwd(newPwd, u.Password) == true {
		return fmt.Errorf("the new password is illegal: it is the same as the current password, please select a new password")
	}
	for _, s := range u.OldPasswords {
		if compareHashedPwd(newPwd, s) == true {
			return fmt.Errorf("the new password is illegal: it was already used, please select a new password")
		}
	}
	return nil
}

// The password should be handled and stored as hashed and not in clear text
// This function implementation may later be updated to crypto.cbytes
func GetHashedPwd(pwd []byte) []byte {
	hasher := sha256.New()
	hasher.Write(pwd)
	return hasher.Sum(nil)
}

func compareHashedPwd(pwd1 []byte, pwd2 []byte) bool {
	return subtle.ConstantTimeCompare(pwd1, pwd2) == 1
}

// Generate a new UserPwd for a given password
// The generated password is with a default expiration time
func NewUserPwd(pwd []byte, saltData []byte) (*UserPwd, error) {
	err := isPwdLengthValid(pwd)
	if err != nil {
		return nil, err
	}
	newPwd, err := salt.GenerateSaltedPassword(pwd, MinPasswordLength, MaxPasswordLength, saltData, -1)
	if err != nil {
		return nil, err
	}
	setPwd := GetHashedPwd(newPwd)
	return &UserPwd{setPwd, saltData, getNewDefaultPasswordExpirationTime(), 0, defaultOneTimePwd, [defaultNumberOfOldPasswords][]byte{}}, nil
}

func getNewDefaultPasswordExpirationTime() time.Time {
	return time.Now().Add(time.Duration(defaultExpirationDurationDays*24) * time.Hour)
}

func (u *UserPwd) SetOneTimePwd(flag bool) {
	u.OneTimePwd = flag
}

// Update password and expiration time
func (u *UserPwd) UpdatePassword(currentPwd []byte, pwd []byte) ([]byte, error) {
	return u.updatePasswordHandler(currentPwd, pwd, getNewDefaultPasswordExpirationTime(), defaultOneTimePwd)
}

// Update the password, it's expioration time and it's state (is it a one-time-password or a regular one)
func (u *UserPwd) updatePasswordHandler(currentPwd []byte, pwd []byte, expiration time.Time, oneTimePwd bool) ([]byte, error) {
	pLock.Lock()
	defer pLock.Unlock()

	err := isPwdLengthValid(pwd)
	if err != nil {
		return nil, err
	}
	err = u.isPasswordMatchHandler(currentPwd, true)
	if err != nil {
		return nil, err
	}
	tmpPwd, err := salt.GenerateSaltedPassword(pwd, MinPasswordLength, MaxPasswordLength, u.Salt, -1)
	if err != nil {
		return nil, fmt.Errorf("problems while generating the new password: %v", err)
	}
	err = u.IsNewPwdValid(tmpPwd)
	if err != nil {
		return nil, err
	}
	newPwd := GetHashedPwd(tmpPwd)
	copy(u.OldPasswords[1:], u.OldPasswords[:])
	u.OldPasswords[0] = u.Password
	u.Password = newPwd
	u.Expiration = expiration
	u.ErrorsCounter = 0
	u.SetOneTimePwd(oneTimePwd)
	return newPwd, nil
}

// Verify that the given password is the expected one and that it is not expired
func (u *UserPwd) IsPasswordMatch(pwd []byte) error {
	return u.isPasswordMatchHandler(pwd, false)
}

// Verify that the given password is the expected one and that it is not expired
// If the overrideChecks is set, do not check the errorCounter and expiration, it uses for passwordUpdate
func (u *UserPwd) isPasswordMatchHandler(pwd []byte, overrideChecks bool) error {
	p1Lock.Lock()
	defer p1Lock.Unlock()

	if overrideChecks == false {
		if u.ErrorsCounter >= maxPwdAttempts {
			return fmt.Errorf("too many password attempts, Reset password before trying again")
		}
		err := isPwdLengthValid(pwd)
		if err != nil {
			return err
		}
		// If the password expired, don't check it
		if time.Now().After(u.Expiration) {
			return fmt.Errorf("password has expired, please replace it.")
		}
	}
	// the error counter must be increased also for password update to avoid backdoors
	if compareHashedPwd(pwd, u.Password) == false {
		u.ErrorsCounter = u.ErrorsCounter + 1
		return fmt.Errorf("password is wrong, please try again")
	} else {
		if u.OneTimePwd == true {
			u.Expiration = time.Now()          // The password expired => it can't be used any more.
			u.SetOneTimePwd(defaultOneTimePwd) // Reset to the default option for the next password
		}
		u.ErrorsCounter = 0
		return nil
	}
}

// Reset the password of a given user to a random password and make it a One-time-password with
// a short window time in which it should be used and replaced by the user
func (u *UserPwd) ResetPasword() ([]byte, error) {
	pass := GenerateNewValidPassword()
	expiration := time.Now().Add(time.Duration(defaultOneTimePwdExpirationMinutes) * time.Second * 60)
	u.ErrorsCounter = 0
	_, err := u.updatePasswordHandler(u.Password, pass, expiration, true)
	u.SetOneTimePwd(true)
	u.Expiration = expiration // to override the one time password setting
	if err != nil {
		return nil, err
	}
	return pass, nil
}

func (u *UserPwd) UpdatePasswordAfterReset(currentPwd []byte, pwd []byte, expiration time.Time) ([]byte, error) {
	return u.updatePasswordHandler(currentPwd, pwd, expiration, false)
}

func CheckPasswordStrength(pass string) error {
	extraCnt := 0
	digitCnt := 0
	upperCaseCnt := 0
	lowerCaseCnt := 0

	for _, c := range extraCharStr {
		extraCnt += strings.Count(pass, string(c))
	}
	for _, c := range digitStr {
		digitCnt += strings.Count(pass, string(c))
	}
	for _, c := range pass {
		if unicode.IsUpper(c) {
			upperCaseCnt++
		}
		if unicode.IsLower(c) {
			lowerCaseCnt++
		}
	}
	if len(pass) < MinPasswordLength || extraCnt < minExtraChars || digitCnt < minDigits ||
		len(pass)-extraCnt-digitCnt < minRegularCnt || upperCaseCnt < minUpperCase || lowerCaseCnt < minLowerCase {
		return fmt.Errorf("The password is not strong enough: it must contains a minimum of %v characters, include at least %v digits, at least %v letters (with at least %v uppercase and %v lowercase letters) and at least %v extra charachters from the following list %v", MinPasswordLength, minDigits, minRegularCnt, minUpperCase, minLowerCase, minExtraChars, extraCharStr)
	}
	return nil
}

// Generate a valid password that includes defaultPasswordLen characters
// with 2 Upper case characters, 2 numbers and 2 characters from "!@#$&-+;"
// The other method of select random byte array and verify if it fits the rules may take a lot of
// iterations to fit the rules
// The entropy is not perfect but its good enougth for one time reset password
func GenerateNewValidPassword() []byte {
	extraChars := []byte(extraCharStr)
	pwd := make([]byte, defaultPasswordLen)
	_, err := io.ReadFull(rand.Reader, pwd)
	if err != nil {
		panic(fmt.Errorf("random read failed: %v", err))
	}
	// Entropy is not the best: random is 0-255 map to 0-21
	for i := 0; i < defaultPasswordLen; i++ {
		if pwd[i] < 'a' || pwd[i] > 'z' {
			pwd[i] = (pwd[i] % ('z' - 'a')) + 'a'
		}
	}

	// Replace 6 characters with 2 Upper case characters, 2 digits and 2 extra characters
	for j := 0; j < 6 && j < defaultPasswordLen; j++ {
		if j < 2 {
			pwd[j] = pwd[j] - 'a' + 'A'
		} else if j >= 2 && j < 4 {
			// entropy is not the best map 0-21 to 0-9
			pwd[j] = (pwd[j] % 10) + '0'
		} else {
			// entropy is not the best map 0-21 to 0-12
			pwd[j] = extraChars[int(pwd[j])%len(extraChars)]
		}
	}

	// Shuffle the characters of the password except of the first one that must be a letter
	// The first char is allways upper case
	shuffleIterations := 100
	buf := make([]byte, shuffleIterations*2)
	_, err = io.ReadFull(rand.Reader, buf)
	for i := 0; i < shuffleIterations*2-1; i += 2 {
		idx := int(buf[i])%(len(pwd)-2) + 1
		pwd[idx], pwd[idx+1] = pwd[idx+1], pwd[idx]
	}
	return pwd
}

func (s Serializer) PrintProperties(data interface{}) string {
	d, ok := data.(*UserPwd)
	if ok == false {
		return "can't print the Password property its not in the right type"
	}
	return d.String()
}

func (s Serializer) IsEqualProperties(da1 interface{}, da2 interface{}) bool {
	d1, ok1 := da1.(*UserPwd)
	d2, ok2 := da2.(*UserPwd)
	if ok1 == false || ok2 == false {
		return false
	}
	return reflect.DeepEqual(d1, d2)
}

// Store User data info to the secure_storage
func (s Serializer) AddToStorage(prefix string, data interface{}, storage *ss.SecureStorage) error {
	d, ok := data.(*UserPwd)
	if ok == false {
		return fmt.Errorf("can't store the Password property: its not in the right type")
	}
	if storage == nil {
		return fmt.Errorf("can't add Password property to storage, storage is nil")
	}
	value, _ := json.Marshal(d)
	err := storage.AddItem(prefix, string(value))
	if err != nil {
		return err
	}
	return nil
}

// Read the user information from disk (in JSON format)
func (s Serializer) ReadFromStorage(key string, storage *ss.SecureStorage) (interface{}, error) {
	var user UserPwd

	if storage == nil {
		return nil, fmt.Errorf("can't read Password property from storage, storage is nil")
	}
	value, exist := storage.Data[key]
	if !exist {
		return nil, fmt.Errorf("key '%v' was not found in storage", key)
	}
	err := json.Unmarshal([]byte(value), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
