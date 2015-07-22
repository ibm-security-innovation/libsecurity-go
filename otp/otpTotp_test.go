package otp

import (
	"fmt"
	"testing"
	"time"
)

func testGetTotp(t *testing.T) *Totp {
	totp, err := NewTotp(BaseSecret)
	if err != nil {
		t.Error("Test fail,", err)
		t.FailNow()
	}
	return totp
}

// Verify that an error is generated only for an illegal lifespan
func Test_TotpIllegalInterval(t *testing.T) {
	totp := testGetTotp(t)

	for i := 0; i < maxIntervalSec+2; i++ {
		totp.Interval = time.Second * time.Duration(i)
		_, err := totp.Now()

		if err == nil && (i < minIntervalSec || i > maxIntervalSec) { // The next error does not make sense to me:
			t.Error(fmt.Sprintf("Totp test failed: initialization was done for illegal interval duration %v, valid range should be (%vs-%vs)",
				time.Second*time.Duration(i), minIntervalSec, maxIntervalSec))
		} else if err != nil && (i >= minIntervalSec && i <= maxIntervalSec) {
			t.Error(fmt.Sprintf("Totp test failed: Otp init fail for legal interval duration %vs, error: %v", i, err))
		}
	}
}

// Verify that Different parameters (secret keys, digits, digests) result with different generated OTPs
func Test_OtpOTPParamesChanged(t *testing.T) {
	res := make(map[string]TotpRun)
	for _, data := range referenceRunsTotp {
		if _, exists := res[data.result]; exists {
			t.Error("Runs with different parameters but returns the same otp: ", res[data.result], data)
		} else {
			t.Log("New OTP data:", data, "was not found in structure, so add it")
			res[data.result] = data
		}
	}
}

func setStateTotp(ot *Totp, state TotpRun) {
	ot.BaseOtp.Secret = state.totp.BaseOtp.Secret
	ot.BaseOtp.digest = state.totp.BaseOtp.digest
	ot.BaseOtp.Digits = state.totp.BaseOtp.Digits
	ot.Interval = time.Second * state.totp.Interval
}

// Verify that increments within the defined lifespan of a TOTP result with identical OTPs and
// time increments larger than the defined lifespan of a TOTP result with different OTPs
func Test_OtpTestTotp(t *testing.T) {
	totp := testGetTotp(t)

	intervalCalc := interval[0]
	timeOffset := []time.Duration{0 * time.Second, intervalCalc / 2, intervalCalc + (1 * time.Second)}

	for _, offset := range timeOffset {
		for _, data := range referenceRunsTotp {
			setStateTotp(totp, data)
			val, err := data.totp.AtTime(data.at.Add(offset))
			if err != nil {
				t.Error("Test fail before running, illigal parameters:", err)
				continue
			}
			if offset < data.totp.Interval {
				if val != data.result {
					t.Error("OTP unexpectedly changed during defined lifespan :", data, "original run time -", data.at,
						"curent run time -", data.at.Add(offset), " time offset -", offset,
						"defined lifespan -", data.totp.Interval,
						", original OTP:", data.result, "is different from the resultant OTP -", val)
				} else {
					t.Log("OTP value during defined lifespan", offset, "was not changed, as expected")
				}
			}
			//the == is risky: for race conditions
			if offset >= data.totp.Interval {
				if val == data.result {
					t.Error("OTP value did not expire when lifespan expired:", data,
						"original run time -", data.at, ", current run time", data.at.Add(offset),
						", time offset -", offset, ", defined lifespan -", data.totp.Interval,
						"but the OTP calculated value was the same -", val)
				}
			} else {
				t.Log("OTP value out of defined lifespan", offset, "was changed, as expected")
			}
		}
	}
}
