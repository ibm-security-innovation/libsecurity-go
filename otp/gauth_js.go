package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Porting of the JS implementation of Google Authenticator
// presented in http://fiddle.jshell.net/russau/ch8PK/show/light/?secret=abcd

func base32tohex(base32 string) string {
	base32chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	bits := ""
	hex := ""
	base32u := strings.ToUpper(base32)

	for i := 0; i < len(base32); i++ {
		val := strings.Index(base32chars, string(base32u[i]))
		// fmt.Println(fmt.Sprintf("%05b", val))
		bits += fmt.Sprintf("%05b", val)
	}

	for i := 0; (i + 4) <= len(bits); i += 4 {
		chunk := bits[i : i+4]
		cval, _ := strconv.ParseInt(chunk, 2, 8)
		chex := fmt.Sprintf("%0x", cval)
		// fmt.Println(chunk, cval, chex)
		hex = hex + chex
	}
	return hex
}

func jsOtp(base32secret string, epoch int64) string {
	key := base32tohex(base32secret)
	time := fmt.Sprintf("%016x", epoch/30)
	//fmt.Println(key,epoch,time)

	k, _ := hex.DecodeString(key)
	v, _ := hex.DecodeString(time)
	hm := hmac.New(sha1.New, k)
	hm.Write(v)
	hmcout := hex.EncodeToString(hm.Sum(nil))

	offset, _ := strconv.ParseInt(hmcout[len(hmcout)-1:], 16, 64)
	substr := hmcout[offset*2 : offset*2+8]
	psubstr, _ := strconv.ParseInt(substr, 16, 64)
	pmask, _ := strconv.ParseInt("7fffffff", 16, 64)
	otpEx := fmt.Sprintf("%d", psubstr&pmask)
	// fmt.Println(offset,otp_ex[len(otp_ex)-6:])
	return otpEx[len(otpEx)-6:]
}
