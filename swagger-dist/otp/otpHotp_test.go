package otp

import (
	"testing"
)

func setStateHotp(ot *Hotp, state HotpRun) {
	ot.BaseOtp.Secret = state.hotp.BaseOtp.Secret
	ot.BaseOtp.digest = state.hotp.BaseOtp.digest
	ot.BaseOtp.Digits = state.hotp.BaseOtp.Digits
	ot.Count = state.hotp.Count
}

func testGetHotp(t *testing.T) *Hotp {
	hotp, err := NewHotp(BaseSecret, defaultStartCounter)
	if err != nil {
		t.Error("Test fail,", err)
		t.FailNow()
	}
	return hotp
}

// Verify that different counter values with the same counter seed as well as identical counter values with different counter seeds result with different OTPs and
// identical counter values with identical counter seeds result with identical OTPs
func Test_OtpTestHotpAtCount(t *testing.T) {
	hotp := testGetHotp(t)
	counterOffset := []int64{0, -1, 1, 12345}

	for _, offset := range counterOffset {
		for _, data := range referenceRunsHotp {
			setStateHotp(hotp, data)
			val, err := data.hotp.AtCount(data.counter + offset)
			if err != nil {
				t.Error("Test fail before running, illigal parameters:", err)
				continue
			}
			if offset == 0 {
				if val != data.result {
					t.Error("OTP did not change after incrementing the counter even though all other parameters, including the seed counter, are identical:", data,
						"original seed -", data.counter, ", curent seed -", data.counter+offset,
						"but the OTP -", data.result, "is different from the resultant OPT -", val)
				} else {
					t.Log("OTP calculated value for the same seed stays the same (as expected)")
				}

			}
			if offset != 0 {
				if val == data.result {
					t.Error("OTP value did not change when the seed counter changed (all other parameters remained identical) :", data,
						"original seed -", data.counter, ", curent seed -", data.counter+offset,
						"but the OTP calculated value was the same", val)
				} else {
					t.Log("OTP calculated value for different seed changed (as expected)")
				}
			}
		}
	}
}

// If all parameters are the same, the resultant OTP should be repetative
// If the OTP request start counter was changed (either a different counter or the use use of .Next() or .New()) and
//   all other parameters are the same, the resultant OTP should be different
func Test_OtpTestHotpNextNew(t *testing.T) {
	hotp := testGetHotp(t)
	funcCall := [](func() (string, error)){hotp.New, hotp.Next}

	for i, f := range funcCall {
		for _, data := range referenceRunsHotp {
			setStateHotp(hotp, data)
			val, err := f()
			if val == data.result {
				val, err = f() // give it another chance
			}
			if err != nil {
				t.Error("Test fail before running, illigal parameters:", err)
				continue
			}
			if val == data.result {
				t.Error("OTP value did not change when the seed counter changed",
					"(all other parameters remained identical). Using function:", i, "(0: .New(), 1: .Next())) must return different OTP values:", data,
					"but the OTP calculated value was the same", val)
			} else {
				//	t.Log("OTP calculated value for different seed due to .next/.new call was changed (as expected)")
			}
		}
	}
}

// WIll check a loop of 11, from a referance counter of -5 to +5
// The only time it should get the same results is when the counters are the same
func Test_OtpTestHotpAccuracy(t *testing.T) {
	hotp := testGetHotp(t)
	shift := int64(5)

	for _, data := range referenceRunsHotp {
		data.hotp.Count = data.hotp.Count - shift - 1
		setStateHotp(hotp, data)
		for i := -shift; i < shift+1; i++ {
			val, err := data.hotp.Next()
			if err != nil {
				t.Error("Test fail before running, illigal parameters:", err)
				break
			}
			if i != 0 && val == data.result {
				t.Error("OTP value did not change when the seed counter changed",
					"(all other parameters remained identical) :", data,
					"but the OTP calculated value was the same:", val)
			}
			if i == 0 && val != data.result {
				t.Error("OTP value modified even though all parameters",
					"as well as the counter value and seed counter are identical: ", data,
					"OTP", val, "is different from the result OTP:", data.result)
			}
		}
	}
}
