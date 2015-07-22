// A One Time Password (OTP) is a password that is valid for only one login session or transaction (and may be limited for a specific time period). The most important advantage that is addressed by OTPs is that, in contrast to static passwords, they are not vulnerable to replay attacks. A second major advantage is that a user who uses the same (or similar) password for multiple systems, is not made vulnerable on all of them, if the password for one of these is gained by an attacker.
// We implemented the 2 possible OTP implementations: A time based one time password algorithm (TOTP) and HMAC-based one time password algorithm (HOTP). Our OTP implementation is based on RFC 2289 for OTP in general, RFC 4226 for HOTP, and RFC 6238 for TOTP.
//
// The OTP implementation has three layers:
//	- The base layer includes the secret (e.g. SHA256, SHA1) and the number of digits in the digest.
//	- The second layer is the digest algorithm which is time based for TOTP and counter based for HOTP.
//	- The topmost layer includes the policy of handing unsuccessful authentication attempts. This includes blocking and throttling. The blocking mechanism allows blocking users for a given duration of time (or until a manual unblock) after they pass a cliff which a limit for the number of allowed consecutive unsuccessful authentication attempts. The throttling mechanism controls the delay between the authentication request and the response. This delay is increased as the number of consecutive unsuccessful attempts grows to avoid brute force password attacks. This layer includes also a time window for avoiding clock drifting errors when TOTPs are used.
//
// OTP per user:
//	Each OTP property has the following fields:
//	- Secret - the password itself
//	- Blocked  - a flag indicating if the user is blocked
//	- Throttling parameters - Handling of all the throttle parameters (details below), including:
//	- HOTP information: Current counter and OTP data (details below)
//	- TOTP information:  Interval, the time interval in seconds which is counted as a 'tick' (e.g. 30 seconds) and OTP data (details bellow)
package otp

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	stc "ibm-security-innovation/libsecurity-go/defs"
	ss "ibm-security-innovation/libsecurity-go/storage"
)

type OtpType int

const (
	defaultStartCounter       = 1000
	defaultThrottlingLen      = 10
	defaultThrottlingSec      = 1
	defaultUnblockSec         = 3600 // 0 means manuel unblock
	manuelUnblockSec          = 0
	defaultHotpWindowsSize    = 3
	defaultTotpWindowsSizeSec = -30
	defaultConsErrorCounter   = 0

	minThrottlingCounter = 10
	maxThrottlingCounter = 10000
	minThrottlingSec     = 0
	maxThrottlingSec     = 5
	minHotpWindowSize    = 1 // the search window will be inclusive this value
	maxHotpWindowSize    = 5
	minTotpWindowSizeSec = -240
	maxTotpWindowSizeSec = 240
	maxUnblockSec        = 3600

	HotpType OtpType = 1
	TotpType OtpType = 2
)

type throtteling struct {
	Cliff               int32         // The provider will refuse connections from a user after T unsuccessful authentication attempts, Default is 100
	DurationSec         time.Duration // Throttling duration in seconds between each wrong atempt
	throttlingTimerHotp time.Time     // Next time the code could be verified for HOTP
	throttlingTimerTotp time.Time     // Next time the code could be verified for TOTP
	CheckHotpWindow     time.Duration // The window size of next codes to be checked before reject the code as not match
	consErrorCounter    int32         // Counter of consecutive errors
	AutoUnblockSec      time.Duration // Number of seconds to release block, 0 means that the release should be manuel
	unblockTimer        time.Time     // When to unblock the user
	CheckTotpWindowSec  time.Duration // The window size in seconds tfor backword check: to handle clock driffts
	lastTotpCode        string        // save the last totp code to avoid reuse of code in the same time period
}

func (t throtteling) String() string {
	return fmt.Sprintf("Cliff: %v, Durattion Sec: %v, HotpWindow %v, Auto unblock: %v, TotpWIndowSizeSec %v",
		t.Cliff, t.DurationSec, t.CheckHotpWindow, t.AutoUnblockSec, t.CheckTotpWindowSec)
}

type OtpUser struct {
	Secret   []byte
	Blocked  bool
	Throttle throtteling // Handle all the throttle parameters
	BaseHotp *Hotp
	BaseTotp *Totp
}

func (u OtpUser) String() string {
	return fmt.Sprintf("Otp parameters: is blocked: %v, Throttling: %v, total consecutive errors: %v",
		u.Blocked, u.Throttle, u.Throttle.consErrorCounter)
}

type Serializer struct{}

func init() {
	stc.Serializers[stc.OtpPropertyName] = &Serializer{}
}

func (u OtpUser) isValid() error {
	return u.Throttle.isValid()
}

func newThrottle(cliffLen int32, thrTimeSec time.Duration, autoUnblockSec time.Duration, hotpWindowSize time.Duration, totpWindowSize time.Duration) throtteling {
	return throtteling{
		cliffLen,
		thrTimeSec,
		getBeginningOfTime(),
		getBeginningOfTime(),
		hotpWindowSize,
		defaultConsErrorCounter,
		autoUnblockSec,
		getBeginningOfTime(),
		totpWindowSize,
		"",
	}
}

func (t throtteling) isValid() error {
	if t.Cliff < minThrottlingCounter || t.Cliff > maxThrottlingCounter {
		return fmt.Errorf("user struct is not valid, the used throttling counter (%v) is not in the allowed range (%v-%v)", t.Cliff, minThrottlingCounter, maxThrottlingCounter)
	}
	if t.DurationSec < minThrottlingSec || t.DurationSec > maxThrottlingSec {
		return fmt.Errorf("user struct is not valid, the used throttling duration value (%vs) is not in the allowed range (%vs-%vs)", t.DurationSec, minThrottlingSec, maxThrottlingSec)
	}
	if t.AutoUnblockSec > maxUnblockSec {
		return fmt.Errorf("user struct is not valid, the automatic user unblock is %vs, which is higher than the allowed %vs", t.AutoUnblockSec, maxUnblockSec)
	}
	if t.CheckHotpWindow < minHotpWindowSize || t.CheckHotpWindow > maxHotpWindowSize {
		return fmt.Errorf("user struct is not valid, the used Hotp check window (%v) is not in the allowed range: %v-%v", t.CheckHotpWindow, minHotpWindowSize, maxHotpWindowSize)
	}
	if t.CheckTotpWindowSec < minTotpWindowSizeSec || t.CheckTotpWindowSec > maxTotpWindowSizeSec {
		return fmt.Errorf("user struct is not valid, the used Totp check window in sec (%v) is not in the allowed range: %vs-%vs", t.CheckTotpWindowSec, minTotpWindowSizeSec, maxTotpWindowSizeSec)
	}
	if maxThrottlingCounter-t.consErrorCounter < minThrottlingCounter {
		return fmt.Errorf("user struct is not valid, the initial value of consecutive errors (%v) is larger than Maximum allowed - %v", t.consErrorCounter, maxThrottlingCounter-minThrottlingCounter)
	}
	return nil
}

func NewSimpleOtpUser(secret []byte) (*OtpUser, error) {
	return NewOtpUser(secret, false, defaultThrottlingLen, defaultThrottlingSec, defaultUnblockSec, defaultHotpWindowsSize, defaultTotpWindowsSizeSec, defaultStartCounter)
}

func NewOtpUser(secret []byte, lock bool, cliffLen int32, thrTimeSec time.Duration, autoUnblockSec time.Duration, hotpWindowSize time.Duration, totpWindowSize time.Duration, startCount int64) (*OtpUser, error) {
	hotp, err := NewHotp(secret, startCount)
	if err != nil {
		return nil, err
	}
	totp, err := NewTotp(secret)
	if err != nil {
		return nil, err
	}
	return &OtpUser{secret, lock,
		newThrottle(cliffLen, thrTimeSec, autoUnblockSec, hotpWindowSize, totpWindowSize),
		hotp, totp}, err
}

func (u *OtpUser) setBlockedState(val bool) {
	u.Blocked = val
	if val == true {
		u.initAutoUnblockTimer()
	}
}

func (u OtpUser) getBlockState() bool {
	return u.Blocked
}

// set the automatic unblock timer
func (u *OtpUser) initAutoUnblockTimer() {
	if u.Throttle.AutoUnblockSec != manuelUnblockSec {
		u.Throttle.unblockTimer = time.Now().Add(time.Duration(u.Throttle.AutoUnblockSec) * time.Second)
		if debug {
			fmt.Println("Current time:", time.Now(), "Set the automatic unblock to", u.Throttle.unblockTimer)
		}
		// TODO add relevant log
	}
}

// get the automatic unblock timer
func (u OtpUser) getAutoUnBlockedTimer() time.Time {
	return u.Throttle.unblockTimer
}

func getBeginningOfTime() time.Time {
	return time.Date(1970, time.January, 1, 1, 0, 0, 0, time.Local)
}

func (u *OtpUser) checkAndUpdateUnBlockStateHelper(timeOffset time.Duration) {
	if u.getBlockState() && u.Throttle.AutoUnblockSec != manuelUnblockSec {
		if time.Now().Add(time.Duration(timeOffset) * time.Second).After(u.Throttle.unblockTimer) {
			u.setBlockedState(false)
			u.Throttle.consErrorCounter = 0 // TODO is it OK, nothing in the RFC
			//  TODO add log
		}
	}
}

// if the user shuld be unblocked because the blocked time was passed, unblock it
func (u *OtpUser) checkAndUpdateUnBlockState() {
	u.checkAndUpdateUnBlockStateHelper(0)
}

// Check if the input code match the expected code in a given window size
func (u *OtpUser) findHotpCodeMatch(code string, size int32) (bool, int32, error) {
	var i int32
	for i = 0; i < size; i++ {
		calcCode, err := u.BaseHotp.AtCount(u.BaseHotp.Count + int64(i))
		if debug {
			fmt.Println("calc code", calcCode, "compare with", code, "counter", u.BaseHotp.Count+int64(i))
		}
		if err != nil {
			return false, i, err // error must be checked before return value, to be on the safe side teh return is false
		}
		if code == calcCode {
			return true, i, nil // the update of the counter offset must be done in the higher level
		}
	}
	return false, 0, nil // no match
}

// Check if the input code match the expected code in a given window time
func (u *OtpUser) findTotpCodeMatch(code string, timeOffsetSec int32) (bool, error) {
	var start, last int64
	offset := int64(timeOffsetSec)
	calcCode, _ := u.BaseTotp.Now()
	if code == calcCode {
		if debug {
			fmt.Println("Code", code, "was found with no offset")
		}
		return true, nil
	}
	if offset > 0 {
		start = 1
		last = offset
	} else {
		start = offset
		last = 1
	}
	for i := start; i <= last; i += int64(u.BaseTotp.Interval.Seconds()) {
		calcCode, err := u.BaseTotp.AtTime(time.Now().Add(time.Duration(i) * time.Second))
		if debug {
			fmt.Println("calc code:", calcCode, ", compare with:", code, ", offset:", i,
				"window size:", timeOffsetSec, "time now:", time.Now(), "calc time:", time.Now().Add(time.Duration(i)*time.Second))
		}
		if err != nil {
			return false, err // error must be checked before return value, to be on the safe side teh return is false
		}
		if code == calcCode {
			return true, nil // the update of the counter offset must be done in the higher level
		}
	}
	return false, nil // no match
}

func (u *OtpUser) handleErrorCode(otpType OtpType) (bool, error) {
	if u.Throttle.consErrorCounter < u.Throttle.Cliff {
		u.Throttle.consErrorCounter++
		factor := int64(u.Throttle.consErrorCounter) * int64(u.Throttle.DurationSec) // was int32(math.Pow(2, float64(u.consErrorCounter))) * u.ThDurationSec
		timer := time.Now().Add(time.Duration(factor) * time.Second)
		if otpType == HotpType {
			u.Throttle.throttlingTimerHotp = timer
		} else {
			u.Throttle.throttlingTimerTotp = timer
		}
		if debug {
			fmt.Println("Error cnt", u.Throttle.consErrorCounter, "set throttling timer to", timer,
				"factor", factor, "add", time.Duration(factor)*time.Second, "Throttle DurationSec", u.Throttle.DurationSec)
		}
		return false, nil
	}
	u.setBlockedState(true)
	u.initAutoUnblockTimer()
	return false, fmt.Errorf("Too many false attempts, locked out")
}

func (u *OtpUser) handleOkCode(code string, otpType OtpType, offset int32) (bool, error) {
	if otpType == HotpType && offset != 0 {
		u.BaseHotp.Count += int64(offset) // resync the provider interal counter to the client counter
		// TODO log
	}
	if otpType == HotpType {
		u.Throttle.throttlingTimerHotp = getBeginningOfTime()
		u.BaseHotp.Next()
	} else { // you can't try the code till the next Totp period
		u.Throttle.throttlingTimerTotp = getBeginningOfTime()
		u.Throttle.lastTotpCode = code
	}
	u.Throttle.consErrorCounter = defaultConsErrorCounter // clear the consecutive error counter
	return true, nil
}

// Verify that the given code is the expected one, if so, increment the internal counter (for hotp) or block the same code (for totp)
// The upper layer shell take the action to blocl the user (the upper layer can take more information before blockingthe user)
// the differences between hotp and totp are: the code check and the action if the code was found
func (u *OtpUser) VerifyCode(code string, otpType OtpType) (bool, error) {
	var found bool
	var err error
	var offset int32

	err = u.isValid()
	if err != nil {
		return false, err // false since valid wasn't checked
	}

	if debug {
		fmt.Println("otpType", otpType, "last code", u.Throttle.lastTotpCode, "code", code)
	}
	if otpType == HotpType {
		found, offset, err = u.findHotpCodeMatch(code, int32(u.Throttle.CheckHotpWindow))
	} else {
		if u.Throttle.lastTotpCode == code { // avoid replay attack for totp
			return false, fmt.Errorf("The TOTP Code was already used, you will have to wait for the next time period")
		}
		found, err = u.findTotpCodeMatch(code, int32(u.Throttle.CheckTotpWindowSec))
	}
	if err != nil {
		return false, err // error must be checked before return value, to be on the safe side teh return is false
	}
	if debug {
		fmt.Println("Found code", found)
	}
	if !found {
		return u.handleErrorCode(otpType)
	} else {
		return u.handleOkCode(code, otpType, offset)
	}
}

func (u OtpUser) isOtpUserBlockedHelper(offsetTime time.Duration) (bool, error) {
	u.checkAndUpdateUnBlockStateHelper(offsetTime)
	return u.getBlockState(), nil
}

func (u OtpUser) IsOtpUserBlocked() (bool, error) {
	return u.isOtpUserBlockedHelper(0)
}

func (u *OtpUser) SetOtpUserBlockedState(block bool) error {
	u.setBlockedState(block)
	return nil
}

func (u OtpUser) getOtpUserThrottlingTimer(otpType OtpType) (time.Time, error) {
	if otpType == HotpType {
		return u.Throttle.throttlingTimerHotp, nil
	}
	return u.Throttle.throttlingTimerTotp, nil
}

// OTP shall be verified only if the throttle time is pass and the user is not blocked
func (u *OtpUser) canCheckOtpCode(otpType OtpType, timeFactorSec time.Duration) (bool, error) {
	var timer time.Time

	if otpType == HotpType {
		timer = u.Throttle.throttlingTimerHotp
	} else {
		timer = u.Throttle.throttlingTimerTotp
	}
	if timer.After(time.Now().Add(time.Duration(timeFactorSec) * time.Second)) {
		return false, fmt.Errorf("User must wait till %v before trying again. The current time is: %v",
			timer, time.Now())
	}
	blocked, _ := u.isOtpUserBlockedHelper(timeFactorSec)
	if blocked {
		return false, fmt.Errorf("User is blocked (thus it was not checked), Please unblock the user first")
	}
	return true, nil
}

// Verify that a given code is as expected, If the user is blocked, return an error
// If the code is as expected, the counter code will be incremented (for HOTP) and saved to avoid replay attack (TOTP)
// If the code dosn't match and the number of consecutive errors pass the Throtlling parameter
// for this user, the user acount will be blocked till manuel or automatic unblock
func (u *OtpUser) VerifyOtpUserCode(code string, otpType OtpType) (bool, error) {
	return u.verifyOtpUserCodeHelper(code, otpType, 0)
}

func (u *OtpUser) verifyOtpUserCodeHelper(code string, otpType OtpType, timeFactorSec time.Duration) (bool, error) {
	ok, err := u.canCheckOtpCode(otpType, timeFactorSec)
	if !ok {
		return ok, err
	}
	return u.VerifyCode(code, otpType)
}

func (u *OtpUser) IsEqual(u1 interface{}) bool {
	return reflect.DeepEqual(u, u1.(*OtpUser))
}

func (s Serializer) PrintProperties(data interface{}) string {
	d, ok := data.(*OtpUser)
	if ok == false {
		return "Error: Can't print the OTP property it is not in the right type"
	}
	return d.String()
}

func (s Serializer) IsEqualProperties(da1 interface{}, da2 interface{}) bool {
	t1, ok1 := da1.(*OtpUser)
	t2, ok2 := da2.(*OtpUser)
	if ok1 == false || ok2 == false {
		return false
	}
	// don't comapre the parts that are not saved
	t2.Throttle.throttlingTimerHotp = t1.Throttle.throttlingTimerHotp
	t2.Throttle.throttlingTimerTotp = t1.Throttle.throttlingTimerTotp
	t2.Throttle.consErrorCounter = t1.Throttle.consErrorCounter
	t2.Throttle.unblockTimer = t1.Throttle.unblockTimer
	t2.Throttle.lastTotpCode = t1.Throttle.lastTotpCode
	t2.BaseTotp.BaseOtp.digest = nil
	t1.BaseTotp.BaseOtp.digest = nil
	t2.BaseHotp.BaseOtp.digest = nil
	t1.BaseHotp.BaseOtp.digest = nil
	return reflect.DeepEqual(t1, t2)
}

// Store User data info to the secure_storage
func (s Serializer) AddToStorage(prefix string, data interface{}, storage *ss.SecureStorage) error {
	d, ok := data.(*OtpUser)
	if ok == false {
		return fmt.Errorf("Error: Can't store the OTP property: its not in the right type")
	}
	if storage == nil {
		return fmt.Errorf("Error: can't add OTP property to storage, storage is nil")
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
	var user OtpUser

	if storage == nil {
		return nil, fmt.Errorf("Error: can't read AM property from storage, storage is nil")
	}
	value, exist := storage.Data[key]
	if !exist {
		return nil, fmt.Errorf("Error: key '%v' was not found in storage", key)
	}
	err := json.Unmarshal([]byte(value), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
