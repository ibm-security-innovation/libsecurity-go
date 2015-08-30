package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"time"
)

// Following tests are required (all are implemented here):
// 1. Basic functionality:
//   1.1 Unit tests:
//     1.1.1 Verify that empty secret keys cause an error
//     1.1.2 Verify the validity of the base32 conversion function
//     1.1.3 Verify that the next() function for HOTP works properly
//     1.1.4 The next() and new() functions for event based OPT  generate diferent OPTs
//   1.2 Results accuracy
//     1.2.1 Different parameters[input values?] result with different generated OTPs
//     1.2.2 Repetition: Verify that identical input parameters the same parameters result with identical OTPs (TOTP and HOTP)
//     1.2.3 Time manipulations:
//       1.2.3.1 increments within the defined lifespan of a TOTP result with identical OTPs
//       1.2.3.2 Time increments larger than the defined lifespan of a TOTP result with different OTPs
// 2. External validation:
//   2.1 Test that the OTP results match external code results
// May need to add:
// 1. System check: Client provider
// 2. Resync message in the event based HMAC OTP

var BaseSecret = []byte("Aa@bCDEFGH12345678")

type TotpRun struct {
	totp   *Totp
	at     time.Time
	result string
}

func (t TotpRun) String() string {
	ret := fmt.Sprintf("Data: secret key = %v, digit = %v, digest = %v, interval = %v",
		t.totp.BaseOtp.Secret, t.totp.BaseOtp.Digits, t.totp.BaseOtp.digest, t.totp.Interval)
	return ret
}

type HotpRun struct {
	hotp    *Hotp
	counter int64
	result  string
}

func (t HotpRun) String() string {
	ret := fmt.Sprintf("Data: secret key = %v, digit = %v, digest = %v, counter = %v",
		t.hotp.BaseOtp.Secret, t.hotp.BaseOtp.Digits, t.hotp.BaseOtp.digest, t.hotp.Count)
	return ret
}

var hashes = []func() hash.Hash{sha1.New, sha256.New, md5.New}
var secrets = []string{"ABCDABCD11112222", "AC234123456789012", "ABCDEFG12345691234"}
var digits = []int{6, 7, 8}
var interval = []time.Duration{30 * time.Second, 60 * time.Second}
var startCounter = []int64{0, 12345}

var referenceRunsTotp []TotpRun
var referenceRunsHotp []HotpRun

// initialize the refference structures with setup and expected results
func init() {
	referenceRunsTotp = createReferenceRunsTotp()
	referenceRunsHotp = createReferenceRunsHotp()
}

func createReferenceRunsTotp() []TotpRun {
	var refRunsTotp []TotpRun
	at := time.Now()
	var useTime time.Time

	for _, h := range hashes {
		for _, s := range secrets {
			for _, d := range digits {
				for _, in := range interval {
					useTime = at.Round(in)
					totp, err := NewTotp([]byte(s))
					if err != nil {
						fmt.Println("Error while initializing")
						panic(err)
					}
					totp.Interval = in
					totp.BaseOtp.digest = h
					totp.BaseOtp.Digits = d
					res, err := totp.AtTime(useTime)
					if err != nil {
						fmt.Println("Error while initializing")
						panic(err)
					}
					ref := TotpRun{totp, useTime, res}
					refRunsTotp = append(refRunsTotp, ref)
				}
			}
		}
	}
	return refRunsTotp
}

func createReferenceRunsHotp() []HotpRun {
	var refRunsHotp []HotpRun

	for _, h := range hashes {
		for _, s := range secrets {
			for _, d := range digits {
				for _, c := range startCounter {
					hotp, err := NewHotp([]byte(s), c)
					if err != nil {
						fmt.Println("Error while initializing")
						panic(err)
					}
					hotp.BaseOtp.digest = h
					hotp.BaseOtp.Digits = d
					res, err := hotp.AtCount(c)
					if err != nil {
						fmt.Println("Error while initializing")
						panic(err)
					}
					ref := HotpRun{hotp, c, res}
					refRunsHotp = append(refRunsHotp, ref)
				}
			}
		}
	}
	return refRunsHotp
}
