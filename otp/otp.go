// The OTP package provides implementation of One Time Password (OTP) services as defined by RFCs 4226 (HOTP), 6238 (TOTP).
//
// One time password implemenatation
//	This package implements RFC 6238 "Totp: Time-Based One-Time Password Algorithm"
//	 and RFC 4226 HOTP: "An HMAC-Based One-Time Password Algorithm"
//	 - OTP() implements the lower level common layer
//	 - Totp() (time based OTP) and
//	 - Hotp (counter based OTP) implement the upper layers.
//
// Comments:
//	1. Illegal operations:
//	   1.1. An empty secret key
//	   1.2. Code length other than 6-8 digits (not protected by the code)
//	   1.3. Digest other than MD4, MD5, SHA1, SHA256 or SHA512 (not defined by the RFC)  (not protected by the code)
//	2. The encoding scheme of the secret key is not define by the RFC.
//	   It's the user's responsability to use a legal secret key. The most common encoding
//	   scheme is base32 (as used by the Google Authenticator), therefor
//	   the testing of the code includes converting a string to a legal base32 encoded string.
//	3. The option for resetting a HOTP counter to another value of counter is currently not implemented
//	   as it is defined as an extension in the RFC
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"math/big"
	"sync/atomic"
	"time"
)

const (
	debug = false

	defaultNumOfDigits = 6
	defaultIntervalSec = 30

	minNumOfDigits = 6 // RFC 4226 R4
	minSecretLen   = 4 // TODO 16 // RFC 4226 R6, for OCRA examples it must be 8
	maxSecretLen   = 255
	minIntervalSec = 10
	maxIntervalSec = 60
)

var defaultHashFunc = sha1.New

// One Time Password
type Otp struct {
	Secret []byte           // Assume a legal Secret key
	Digits int              // Number of digits in the code. default is 6
	digest func() hash.Hash // Digest type, default is sha1
}

func (o Otp) String() string {
	return fmt.Sprintf("Otp: Digits: %v", o.Digits)
}

func isNumberOfDigitsValid(val int) error {
	if val < minNumOfDigits {
		return fmt.Errorf("The OTP struct is not valid, the number of digits used %d is less than the minimum (%d)", val, minNumOfDigits)
	}
	return nil
}

func isDigestValid(digest func() hash.Hash) error {
	if digest == nil {
		return fmt.Errorf("The OTP struct is not valid, it must have a hash function, but the current hash is nil")
	}
	return nil
}

func isSecretValid(secret []byte) error {
	if len(secret) < minSecretLen || len(secret) > maxSecretLen {
		return fmt.Errorf("The secret key has an illegal length (%d), the length must be between %d and %d", len(secret), minSecretLen, maxSecretLen)
	}
	return nil
}

func (otp Otp) isDataValid() error {
	err := isNumberOfDigitsValid(otp.Digits)
	if err != nil {
		return err
	}
	err = isDigestValid(otp.digest)
	if err != nil {
		return err
	}
	return nil
}

// Generate Otp
func NewOtpAdvance(secret []byte, numOfDigits int, digest func() hash.Hash) (*Otp, error) {
	err := isSecretValid(secret)
	if err != nil {
		return nil, err
	}
	return &Otp{secret, numOfDigits, digest}, nil
}

// The default OTP: sha1 with 6 digits
// Any number of digits and any (hash) function are allowed
func NewOtp(secret []byte) (*Otp, error) {
	err := isSecretValid(secret)
	if err != nil {
		return nil, err
	}
	return &Otp{secret, defaultNumOfDigits, defaultHashFunc}, nil
}

// Return the OTP for a given input
// Input may either be time (for Totp) or integer (for Hotp)
func (otp Otp) Generate(seed int64) (string, error) {
	if err := otp.isDataValid(); err != nil {
		return "", err
	}
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(seed))
	return otp.GenerateHmac(data), nil
}

// Return the OTP for a given input
// Input is a byte array
func (otp Otp) GenerateHmac(data []byte) string {
	hmacHash := hmac.New(otp.digest, otp.Secret)
	hmacHash.Write(data)
	digest := hmacHash.Sum(nil)
	mask := byte(0xf)
	len := byte(hmacHash.Size())
	// in the RFC example mask is always 0xf but its not OK for MD5 which is 16B length
	if len < mask+4 {
		mask = byte(len - 4)
	}
	offset := int(digest[hmacHash.Size()-1] & mask)
	code := int32(digest[offset]&0x7f)<<24 |
		int32(digest[offset+1]&0xff)<<16 |
		int32(digest[offset+2]&0xff)<<8 |
		int32(digest[offset+3]&0xff)
	code = int32(int64(code) % int64(math.Pow10(otp.Digits)))
	if debug {
		fmt.Printf("Seed %x data %x code %x digest %x\n", otp.Secret, data, code, digest)
	}
	// Old use sFmt := fmt.Sprintf("%%0%dd", otp.Digits)
	// Old use return fmt.Sprintf(sFmt, code)
	return fmt.Sprintf("%0*d", otp.Digits, code)
}

// Time-based One Time Password
type Totp struct {
	Interval time.Duration // The time interval in seconds for OT, The default is 30 seconds (the standard)
	BaseOtp  *Otp
}

func (t Totp) String() string {
	return fmt.Sprintf("Totp: Interval: %v, %v", t.Interval, t.BaseOtp)
}

func validInterval(val time.Duration) bool {
	if val.Seconds() < minIntervalSec || val.Seconds() > maxIntervalSec {
		return false
	}
	return true
}

func (totp Totp) isDataValid() error {
	if !validInterval(totp.Interval) {
		return fmt.Errorf("Totp struct is not valid, the time interval should be between %vs and %vs, but the current interval is %v", minIntervalSec, maxIntervalSec, totp.Interval.Seconds())
	}
	return nil
}

// default lifespan of a Totp is 30 seconds
func NewTotp(secret []byte) (*Totp, error) {
	otp, err := NewOtp(secret)
	if err != nil {
		return nil, err
	}
	return &Totp{
		time.Second * defaultIntervalSec,
		otp,
	}, nil
}

// Return the Time Based One Time Password for the current time
func (tp Totp) Now() (string, error) {
	//	if tp.Interval < time.Second * 1 //
	return tp.AtTime(time.Now()) //TODO check for UTC
}

// Generate an OTP for a given time
func (tp Totp) AtTime(t time.Time) (string, error) {
	if err := tp.isDataValid(); err != nil {
		return "", err
	}
	return tp.BaseOtp.Generate(tp.timeCode(t))
}

// A counter that is incremented each lifespan - all
// times within the same timespan return the same value,
// once the time is incremented by the defined lifespan the
// return value is incremented as well
func (tp Totp) timeCode(t time.Time) int64 {
	return (t.Unix() / int64(tp.Interval.Seconds()))
}

// Event-based HMAC One Time Password
type Hotp struct {
	Count   int64
	BaseOtp *Otp
}

func (h Hotp) String() string {
	return fmt.Sprintf("Hotp: count: %v, %v", h.Count, h.BaseOtp)
}

func NewHotp(secret []byte, count int64) (*Hotp, error) {
	otp, err := NewOtp(secret)
	if err != nil {
		return nil, err
	}
	return &Hotp{
		count,
		otp,
	}, err
}

// Generate the next OTP in the sequence
func (hp *Hotp) Next() (string, error) {
	newCount := atomic.AddInt64(&hp.Count, 1)
	return hp.AtCount(newCount)
}

// Generate an OTP for a given value
func (hp Hotp) AtCount(count int64) (string, error) {
	return hp.BaseOtp.Generate(count)
}

// Generate a new OTP using a random integer
func (hp *Hotp) New() (string, error) {
	val, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return hp.AtCount(val.Int64())
}
