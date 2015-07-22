package otp

import (
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Base32 as defined in RFC 4648 Base 32 alphabet
// Convert a given string to Byte32 (upper case, unknown chars + 0,1,l will be converted to 'O')
// The length of the string should be a multiple of 40 bites on base32
// Note that the values for ilegal characters are not defined so I used "O"
func ConvertToLegalBase32(str string, t *testing.T) string {
	base32chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	pad := "O"
	orgLen := len(str)

	length := ((len(str)-1)/8 + 1) * 8
	t.Log("Original string:", str, ", length:", len(str), ", the new base32 len", length)
	for i := len(str); i < length; i++ {
		str = pad + str
	}
	ret := []byte(strings.ToUpper(str))
	for i := length - orgLen; i < len(ret); i++ {
		if strings.IndexByte(base32chars, ret[i]) == -1 {
			ret[i] = 'O'
		}
	}
	t.Log("Converted to base32 string", string(ret))
	return string(ret)
}

// Check the base32 conversion
func Test_ChangedToLegalBase32(t *testing.T) {
	secrets := [][]string{{"abc", "OOOOOABC"}, {"a0123", "OOOAOO23"},
		{"aBn:{}()laA", "OOOOOABNOOOOOLAA"}}
	for _, str := range secrets {
		res := ConvertToLegalBase32(str[0], t)
		if res != str[1] {
			t.Error("Base32 test: Conversion of the string", str[0], "is not as expected (", str[1], ") received: ", res)
		} else {
			t.Log("Conversion of string (", str[1], ") to (", res, ") is as expected")
		}
	}
}

// Verify that an error is generated only for illegal secret key length
func Test_OtpIllegalSecret(t *testing.T) {
	secret := make([]byte, maxSecretLen+10)

	for i := 0; i < maxSecretLen+10; i++ {
		_, err := NewOtp(secret[:i])
		if err == nil && (i < minSecretLen || i > maxSecretLen) {
			t.Error(fmt.Sprintf("Test failed: initialization was done for a secret key with an illegal length %d. Valid lengths are in the range %d-%d", i, minSecretLen, maxSecretLen))
		} else if err != nil && (i >= minSecretLen && i <= maxSecretLen) {
			t.Error(fmt.Sprintf("Test failed: Otp initialization failed for a secret key with a legal length %d, error: %v", i, err))
		}
	}
}

// Test sha1 6 digits with varius secret keys against the Google authenticator calculations
// The input string is converted into a valid base32 string (without undefined characters and with the appropriate length)
func Test_OtpTestTotpVsGoogleAuthenticator(t *testing.T) {
	var val, ref, secret string
	b32secret := [][]string{{"JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"},
		{"ABCD2345", "ABCD2345"}, {"a123", "OOOOAO23"},
		{"abcA(){}AA", "OOOOOOABCAOOOOAA"}}
	totp, err := NewTotp(BaseSecret)
	if err != nil {
		t.Error("Test fail,", err)
		t.FailNow()
	}

	totp.BaseOtp.digest = sha1.New
	totp.BaseOtp.Digits = 6
	totp.Interval = time.Second * 30

	for _, s := range b32secret {
		secret = ConvertToLegalBase32(s[0], t)
		if secret != s[1] {
			t.Error("Base32 test: Conversion of the string", s[0], "is not as expected (", s[1], ") received: ", secret)
			continue
		}
		totp.BaseOtp.Secret, _ = base32.StdEncoding.DecodeString(secret)
		val, err = totp.Now()
		if err != nil {
			t.Error("Test fail before running, illigal parameters:", err)
			continue
		}
		ref = jsOtp(secret, (time.Now().UnixNano()+500000000.0)/1000000000.0)
		if val != ref {
			t.Error("Error: internal OTP value:", val, "is different from the external OTP value :", ref,
				"for the same data: sha1, #of digits", totp.BaseOtp.Digits, "secret", secret)
		} else {
			t.Log("The same internal and external OTP calculation using secret:", secret)
		}
	}
}
