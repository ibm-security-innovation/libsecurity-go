package otp

import (
	"fmt"
	"testing"
	"time"
)

// TODO add totp tests: repalay attack and time drift

const (
	wrongCode = "1234"
)

func testGenerateOtpUser(t *testing.T, thrTimeSec time.Duration) *UserInfoOtp {
	otpUser, err := NewOtpUser(BaseSecret, true, false, defaultThrottlingLen, thrTimeSec, manuelUnblockSec, defaultHotpWindowsSize, defaultTotpWindowsSizeSec, defaultStartCounter)
	if err != nil {
		t.Errorf("Test fail, can't generate otpUser, error: %v", err)
		t.FailNow()
	}
	return otpUser
}

func addDefaultOtpUserGetHotp(t *testing.T, throttleTimeSec time.Duration) (*UserInfoOtp, *Hotp) {
	otpUser := testGenerateOtpUser(t, throttleTimeSec)
	hotp := testGetHotp(t)
	return otpUser, hotp
}

func addDefaultOtpUserGetTotp(t *testing.T, throttleTimeSec time.Duration) (*UserInfoOtp, *Totp) {
	otpUser := testGenerateOtpUser(t, throttleTimeSec)
	totp := testGetTotp(t)
	return otpUser, totp
}

// Check that the throttling counter delay count as expected (2^num of unsuccessfull retries)
// and the next time the code is checked is after the throttling time pass
func Test_CheckErrorThrottling(t *testing.T) {
	throttleTimeSec := time.Duration(2)
	otpUser, hotp := addDefaultOtpUserGetHotp(t, throttleTimeSec)

	for i := 0; i < 10; i++ {
		refTime := time.Now()
		otpUser.setBlockedState(false)                                          // so the user will not be blocked
		factor := time.Duration(i+1) * throttleTimeSec                          //was int32(math.Pow(2, float64(i))) * throttleTimeSec
		ok, err := otpUser.verifyOtpUserCodeHelper(wrongCode, HotpType, factor) // error codes to increase the delay
		if err != nil {
			t.Error("Test fail, err:", err)
		}
		throttleTimer, err := otpUser.getOtpUserThrottlingTimer(TotpType)
		if err != nil {
			t.Error("Test fail, err:", err)
		} else {
			expected := time.Now().Add(time.Duration(factor) * time.Second)
			if throttleTimer.After(expected) {
				fmt.Printf("Test failed, expected the throttle value to be lower than %v, but the return throttling value was %v. Time now is %v and factor is%v\n",
					expected, throttleTimer, time.Now(), factor)
				t.Errorf("Test failed, expected the throttle value to be lower than %v, but the returned throttling value was %v",
					expected, throttleTimer)
			}
			if i == 0 { // check that the throttling timer work OK for the basic unit
				code, _ := hotp.AtCount(hotp.Count)
				codeOk, _ := otpUser.VerifyOtpUserCode(code, HotpType) // test should not be checked before throttling duration
				if codeOk {
					t.Error("Test fail, Time:", time.Now(), ", OTP shuld not be checked before:", throttleTimer)
				}
				codeOk, err = otpUser.verifyOtpUserCodeHelper(code, HotpType, factor)
				if debug {
					fmt.Println("Calculated code = ", code, ", match = ", ok)
				}
				if !codeOk || err != nil {
					t.Errorf("Test fail, expected to be throttle for: %vs, checked after %v, err: %v",
						throttleTimeSec, time.Now().Unix()-refTime.Unix(), err)
				}
				if codeOk { // advance the internal counter
					hotp.Next()
				}
			}
		}
	}
}

// Test HOTP window size: it should match if the new code uses offset within the windowSize, otherwise, no match
func Test_CheckOtpWindowSizeLowLevel(t *testing.T) {
	windowSize := 5.0
	winSize := int64(windowSize)
	offsets := []float64{-1, 0, windowSize / 2, windowSize - 1, windowSize, windowSize + 1}
	otpUser, hotp := addDefaultOtpUserGetHotp(t, 0)

	for _, o := range offsets {
		offset := int64(o)
		code, _ := hotp.AtCount(hotp.Count + offset)
		found, newOffset, _ := otpUser.findHotpCodeMatch(code, int32(winSize))
		if (offset < 0 || offset >= winSize) && found {
			t.Error("Test fail, Code for offset ", offset, "was found, but the window size for code search is 0 to ", winSize)
		} else if (offset >= 0 && offset < winSize) && !found {
			t.Error("Test fail, Code for offset ", offset, "was not found, but the window size for code search is 0 to", winSize)
		} else if found && newOffset != int32(offset) {
			t.Error("Test fail, Code was found, but the calculated offset:", newOffset, "is not as expected:", offset)
		}
	}
}

type testOffset struct {
	internalCounterOffset int64
	codeOffset            int64
	expected              bool
}

// Test HOTP counter updated when the new code matches advanced counter within the window size
// The test will try to match with the following offsets:
//    maxHotpWindowSize+1 (no match: out of range), maxHotpWindowSize (no match: out of range),
//    maxHotpWindowSize-1 (match, in range) and than internal counter org + 1 (no match): provider counter = org + maxHotpWindowSize > orgCounter + 1
//    see inline for the extra tests
func Test_CheckOtpCounterUpdated(t *testing.T) {
	otpUser, hotp := addDefaultOtpUserGetHotp(t, 0)

	otpUser.Throttle.CheckHotpWindow = maxHotpWindowSize
	otpUser.Throttle.Cliff = maxThrottlingCounter // no block out
	tests := []testOffset{{0, maxHotpWindowSize + 1, false}, {0, maxHotpWindowSize, false},
		{0, maxHotpWindowSize - 1, true},                     // int cnt org, provider cnt org, at the end provider cnt = org + delta
		{0, 1, false},                                        // int cnt org, provider cnt org+delta
		{0, maxHotpWindowSize, true},                         // int cnt org+delta, provider cnt org+delta+1
		{0, maxHotpWindowSize - 1, false},                    // int cnt org+delta-1, provider cnt org+delta+1, at the end: provider cnt = org + delta + 2
		{maxHotpWindowSize + 3, maxHotpWindowSize + 2, true}, // int cnt org+delta+2, provider cnt org+delta+2, at the end: provider cnt = org + delta + 3
		{maxHotpWindowSize, maxHotpWindowSize - 1, true},     // int cnt org+delta+3, provider cnt org+delta+3, at the end: provider cnt = org + delta + 4
	}

	for i, test := range tests {
		code, _ := hotp.AtCount(hotp.Count + test.codeOffset)
		found, err := otpUser.VerifyOtpUserCode(code, HotpType)
		if err != nil {
			t.Error("Test fail, error:", err)
		}
		if found != test.expected {
			t.Error("Test ", i, "fail, provider counter is:", otpUser.BaseHotp.Count,
				"counter used for code calculatations:", hotp.Count+test.codeOffset,
				"expected that the code will be match:", test.expected, "but code match:", found)
		}
		if found {
			hotp.Count += test.internalCounterOffset // advance the internal counter
		}
	}
}

// test that code calculation will be found if its in the drift window size
// For positive offset and negative window (and vise versa), it depend on the time of excution
func Test_CheckOtpTotpWindow(t *testing.T) {
	otpUser, totp := addDefaultOtpUserGetTotp(t, 0)
	otpUser.Throttle.Cliff = maxThrottlingCounter // no block out
	offsets := []int{-62, -25, -2, 0}
	windowsOffsets := []int{-30}
	sign := []int{1, -1}

	for _, s := range sign {
		for _, w := range windowsOffsets {
			w = w * s
			for i, offset := range offsets {
				offset = offset * s
				otpUser.Throttle.lastTotpCode = "" // clear the last match
				otpUser.Throttle.CheckTotpWindowSec = time.Duration(w)
				testTime := time.Now().Add(time.Duration(offset) * time.Second)
				code, _ := totp.AtTime(testTime)
				found, err := otpUser.VerifyOtpUserCode(code, TotpType)
				if debug {
					fmt.Println("Test:", i, "Window offset:", w, "Offset:", offset, ", Code was match:", found)
				}
				if err != nil {
					t.Error("Test fail, error:", err)
				}
				if found && offset*s < w*s {
					t.Error("Test ", i, "fail, Totp code match, but the provider time:", time.Now(),
						"is not in the used time for code calculations:", testTime,
						"window offset:", w, "seconds")
				}
			}
		}
	}
}

// Check that when the user is locked out, after predefined delay it is automatically unblocked
func Test_CheckAutomaticUnblockUser(t *testing.T) {
	offsetsSec := []time.Duration{-2, 0}
	otpUser, hotp := addDefaultOtpUserGetHotp(t, 0)

	otpUser.Throttle.AutoUnblockSec = defaultUnblockSec
	for i := int32(0); i < otpUser.Throttle.Cliff+1; i++ {
		_, err := otpUser.VerifyOtpUserCode(wrongCode, HotpType)
		if err != nil && i < otpUser.Throttle.Cliff {
			t.Error("Test fail, err:", err)
		}
	}
	blocked, _ := otpUser.IsOtpUserBlocked()
	if !blocked {
		t.Error("Test fail, User must be blocked after", otpUser.Throttle.Cliff, "wrong tries")
		t.FailNow()
	}
	expected := time.Now().Add(time.Duration(otpUser.Throttle.AutoUnblockSec) * time.Second)
	throttleAutoUnblockedTimer := otpUser.getAutoUnBlockedTimer()
	if throttleAutoUnblockedTimer.After(expected) {
		t.Errorf("Test fail, expected the throttle value to be till: %v, but the return throttling value was %v",
			expected, throttleAutoUnblockedTimer)
	} else {
		code, _ := hotp.AtCount(hotp.Count)
		for _, o := range offsetsSec {
			otpUser.verifyOtpUserCodeHelper(code, HotpType, otpUser.Throttle.AutoUnblockSec+o)
			blocked, _ := otpUser.isOtpUserBlockedHelper(otpUser.Throttle.AutoUnblockSec + o)
			if !blocked && o < 0 {
				t.Error("Test fail, User must not be automatically unblocked before", otpUser.Throttle.AutoUnblockSec,
					"seconds, but it was unblocked after", otpUser.Throttle.AutoUnblockSec+o, "seconds")
			} else if blocked && o >= 0 {
				t.Error("Test fail, User must be automatically unblocked after", otpUser.Throttle.AutoUnblockSec,
					"seconds, time pass since blocked", otpUser.Throttle.AutoUnblockSec+o, "seconds")
			}
		}
	}
}

// Test change user lock
func Test_ChangeUserBlocked(t *testing.T) {
	blockedStates := []bool{true, false, true}
	otpUser := testGenerateOtpUser(t, 0)

	for _, b := range blockedStates {
		err := otpUser.SetOtpUserBlockedState(b)
		if err != nil {
			t.Errorf("Test fail, can't change OTP user blocked state to %v, error: %v", b, err)
		} else {
			state, _ := otpUser.IsOtpUserBlocked()
			if state != b {
				t.Errorf("Test fail, Otp user lockedOut state set to %v but read %v", b, state)
			}
		}
	}
}

func initBlockedUserTest(t *testing.T) (*UserInfoOtp, int32) {
	otpUser := testGenerateOtpUser(t, 0)
	len := otpUser.Throttle.Cliff - otpUser.Throttle.consErrorCounter
	otpUser.SetOtpUserBlockedState(false)
	return otpUser, len
}

// generate enougth errors to loc the user
// Tests we are checking:
// 1. If the errCnt < throttle, the user is not blocked
// 2. If the errCnt > throttle, the user is blocked
// 3. If the user is not blocked, the right code is clearing the errCounter
// 4. If the user is blocked, the right code dosn't check therefor, it can't clear the errCounter
func Test_BlockAndUnblockUser(t *testing.T) {
	var code string
	var errCnt int32
	otpUser, len := initBlockedUserTest(t)
	// Clear the err counter and use the right code in the following sequence (each one is starting after the previus one is done)
	clearErrcnt := []int32{len / 2, len + 2, len + 10, len + 2}
	clearErrCntIdx := 0
	hotp := testGetHotp(t)

	for i := int32(0); i < len*4; i++ {
		errCnt++
		if errCnt == clearErrcnt[clearErrCntIdx] { // clear the counter and use the right code
			clearErrCntIdx++
			code, _ = hotp.AtCount(hotp.Count)
			errCnt = 0
			otpUser.SetOtpUserBlockedState(false)
		} else if i > len*3 { // when the user is blocked, the right code should not be checked anyway
			code, _ = hotp.AtCount(hotp.Count)
		} else { // use the wrong code to block the user
			code = wrongCode
		}
		ok, err := otpUser.VerifyOtpUserCode(code, HotpType)
		if ok { // advance the internal counter
			hotp.Next()
		}
		locked, _ := otpUser.IsOtpUserBlocked()
		if err != nil && !locked { // locked user return an error and dosn't check the code
			t.Error("Test was not run, error:", err)
			t.FailNow()
		}
		if locked == true && errCnt <= len {
			t.Errorf("Test failed: User was locked before enougth itterations, try=%v, minimum tries=%v, idx=%v", errCnt, len, i)
		} else if locked == false && errCnt > len {
			t.Errorf("Test failed: User was not locked out after: %v wrong tries, the maximum number of tries before locked out are: %v, idx=%v", errCnt, len, i)
		}
	}
}

/*
//func Test_CheckStoreAndLoadOTPUsersInfo(t *testing.T) {
//	usersList := NewUsers()
//	rUsersList := NewUsers()
//	fileName := "./tmp.txt"
//	defer os.Remove(fileName)
//	secret := []byte("1234567890123456")
//	ul := um.NewUsersList()
//
//	for i := 0; i < 10; i++ {
//		id := fmt.Sprintf("%v%v", DefaultUserId, i)
//		u, _ := um.NewUser(id, nil)
//		ul.AddUser(u)
//		testAddDefaultUserToList(usersList, t, id, defaultThrottlingSec, ul)
//		if i%2 == 0 {
//			usersList.SetUserBlockedState(id, true)
//			usersList.UsersList[id].BaseHotp.Count = 1234
//			usersList.UsersList[id].Throttle.Cliff = 222
//			usersList.UsersList[id].Throttle.DurationSec = 15
//			usersList.UsersList[id].Throttle.AutoUnblockSec = 22
//			usersList.UsersList[id].Throttle.CheckHotpWindow = 11
//			usersList.UsersList[id].Throttle.CheckTotpWindowSec = 123
//		}
//	}
//	usersList.StoreInfo(fileName, secret)
//	LoadInfo(fileName, rUsersList, secret)
//	dataWrite, _ := json.Marshal(usersList)
//	dataRead, _ := json.Marshal(rUsersList)
//	if reflect.DeepEqual(dataWrite, dataRead) == false {
//		t.Error("Test fail: the written users list data not equal to the read one.\nwrite:", usersList, "\n read:", rUsersList)
//	}
//}
//

*/
