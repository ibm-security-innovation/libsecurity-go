package ocra

// The tests can be split into 2 types:
// 1. Data validity: Test that only valid dayta is exepted
// 2. Results accuracy:
//    2.1 Calculated results are the same as defined in the RFC examples
//    2.2 Calculated results are the same as calculated by the RFC java code

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"

	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
)

const (
	ocraSuiteDataInputTimeStampTypeOptions = "smh"

	minSecretLen = 4
	maxSecretLen = 255
)

type checkS struct {
	name  string
	valid bool
}

type ocraTestS struct {
	question string
	exp      string
}

type ocraTestDataS struct {
	ocra     UserOcra
	expected bool
}

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)
}

// HOTP-H-t: HMAC function with the hash function H, and the dynamic truncation
//       as described in [RFC4226] to extract a t-digit value, t=0 means that no truncation is performed and the full HMAC value is used for authentication purposes
//       The options for H are: SHA1, SHA256, SHA512
//       The options for t are: 0, 4-10
func Test_OCRACryptoString(t *testing.T) {
	var types = []checkS{{"HOTP", true}, {"TOTP", false}, {"", false}, {"a", false}}
	var hashesS = []checkS{{"sha1", true}, {"sha256", true}, {"", false}, {"sha512", true}, {"md5", false}, {"sh", false}, {"aaaaaaaaaaaaaaabbbbbbbbbbbbbbbb11111111122", false}}
	var valid bool

	for _, ty := range types {
		for _, h := range hashesS {
			for i := 0; i < 12; i++ {
				_, exists := ocraValidOutputLengthMap[i]
				if exists {
					valid = true
				} else {
					valid = false
				}
				exp := valid && ty.valid && h.valid
				str := ty.name + ocraSuiteDigitSplitToken + h.name + ocraSuiteDigitSplitToken + strconv.Itoa(i)
				logger.Info.Println("Test crypto function:", str, "valid", exp)
				res, err := parseCryptoString(strings.ToLower(str))
				if exp && (err != nil || res.name != h.name || (res.length != i && res.length != maxKeyLength)) {
					if err == nil {
						t.Errorf("Test fail: valid crypto function: %s wasn't accepted: hash function name: '%v' hash length %v are not equal to the expected hash name: %v and length: %v", str, res.name, res.length, h.name, i)
					} else {
						t.Errorf("Test fail: valid crypto function: %s wasn't accepted: error: %v", str, err)
					}
				}
				if exp == false && err == nil {
					t.Error("Test fail: illegal crypto function:", str, "accpted, res:", res)
				}
			}
		}
	}
}

// illegal keys to check: empty key, odd length, key includes not hex character, key is too short, key is too long
func Test_OCRAIllegalKeys(t *testing.T) {
	ocraSuite := "OCRA-1:HOTP-SHA1-6:QA08"
	hexChar := '1'
	randIdx := make([]byte, maxSecretLen)
	io.ReadFull(rand.Reader, randIdx)
	key := ""
	hexStr := string(hexChar)

	for i := 0; i < maxSecretLen*8; i++ {
		length := len(key)
		hLength := length / 2 // the hex length is half the key length
		_, err := GenerateOCRAAdvance(ocraSuite, key, "", "11111111", "", "", "")
		if err == nil && (hLength < minSecretLen || hLength > maxSecretLen || length%2 == 1) {
			t.Error("Test fail: Accept illegal key length:", length, length%2 == 1)
		} else if err != nil && hLength >= minSecretLen && hLength <= maxSecretLen && length%2 == 0 {
			t.Error("Test fail: legal key was not accepted, length:", length, "key:", key)
		}
		_, _, err = GenerateOCRA(key)
		if err == nil && (hLength < minSecretLen || hLength > maxSecretLen || length%2 == 1) {
			t.Error("Test fail: Accept illegal key length:", length, length%2 == 1)
		} else if err != nil && hLength >= minSecretLen && hLength <= maxSecretLen && length%2 == 0 {
			t.Error("Test fail: legal key was not accepted, length:", length, "key:", key)
		}
		key = key + hexStr
	}

	eChars := []byte("ghijklmnopqrstuvwxyz")
	eKey := []byte(strings.Repeat(hexStr, (maxSecretLen/2)*2))
	for i, c := range eChars {
		idx := int(randIdx[i]) % (maxSecretLen - 1)
		eKey[idx] = c
		_, err := GenerateOCRAAdvance(ocraSuite, string(eKey), "", "11111111", "", "", "")
		if err == nil {
			t.Errorf("Test fail: Accept illegal key: char at %v is: '%v' and it is not an hex character", idx, string(eKey[idx]))
		}
		eKey[idx] = byte(hexChar)
	}
}

func Test_OCRADataInputQuestion(t *testing.T) {
	ocraSuiteFmt := []string{"OCRA-1:HOTP-SHA1-6:Q%v%02d", "OCRA-1:HOTP-SHA1-6:C-Q%v%02d", "OCRA-1:HOTP-SHA1-6:C-Q%v%02d-T1M"}
	key := "12345678"
	questionN := "1234112233445566778899001122334455667788990011223344556677889900"
	questionB := make([]byte, maxOcraSuiteDataInputQuestionLength)
	var question string

	for _, s := range ocraSuiteFmt {
		for i := ' '; i <= '}'; i++ {
			format := string(i)
			for j := 0; j < 200; j++ {
				if format == ocraSuiteDataInputQuestionAlfabetToken {
					io.ReadFull(rand.Reader, questionB)
					question = string(questionB)
				} else {
					question = questionN
				}
				str := strings.ToLower(fmt.Sprintf(s, format, j))
				_, err := GenerateOCRAAdvance(str, key, "", question, "", "", "")
				if err == nil && (strings.IndexAny(strings.ToLower(format), ocraSuiteDataInputQuestionTypeOptions) == -1 ||
					j < minOcraSuiteDataInputQuestionLength || j > maxOcraSuiteDataInputQuestionLength) {
					t.Error("Test fail: Accept illegal OCRA dataInput question format:", str)
				}
				if err != nil && (strings.IndexAny(format, ocraSuiteDataInputQuestionTypeOptions) != -1 &&
					(j >= minOcraSuiteDataInputQuestionLength && j <= maxOcraSuiteDataInputQuestionLength)) {
					t.Error("Test fail: legal OCRA dataInput question format:", str, "wasn't accpeted, error:", err)
				}
			}
		}
	}
}

func Test_OCRADataInputPassword(t *testing.T) {
	ocraSuiteFmt := []string{"OCRA-1:HOTP-SHA1-6:QN10-%v", "OCRA-1:HOTP-SHA1-6:C-QA10-%v", "OCRA-1:HOTP-SHA1-6:QN10-%v-T1M"}
	key := "12345678"
	question := "1234112233"
	pass := "1234"
	valid := make(map[string]bool)

	for _, p := range passwords {
		valid[p.name] = true
	}
	for _, s := range ocraSuiteFmt {
		for i := 0; i < 600; i++ {
			p := "psha" + fmt.Sprintf("%d", i)
			str := strings.ToLower(fmt.Sprintf(s, p))
			_, err := GenerateOCRAAdvance(str, key, "", question, pass, "", "")
			if err == nil && valid[p] == false {
				t.Error("Test fail: Accept illegal OCRA dataInput password format:", str)
			}
			if err != nil && valid[p] {
				t.Error("Test fail: legal OCRA dataInput password format:", str, "wasn't accpeted, error:", err)
			}
		}
	}
}

func Test_OCRADataInputSession(t *testing.T) {
	ocraSuiteFmt := []string{"OCRA-1:HOTP-SHA1-6:QN10-%v", "OCRA-1:HOTP-SHA1-6:C-QA10-%v", "OCRA-1:HOTP-SHA1-6:C-QA10-%v-T1H"}
	key := "12345678"
	question := "1234112233"

	for _, s := range ocraSuiteFmt {
		for i := 0; i < 20; i++ { // TODO 2000
			session := "s" + fmt.Sprintf("%d", i)
			str := strings.ToLower(fmt.Sprintf(s, session))
			_, err := GenerateOCRAAdvance(str, key, "", question, "", "", "")
			if err == nil && (i < 100 || i > 999) {
				t.Error("Test fail: Accept illegal OCRA dataInput session format:", str)
			}
			if err != nil && i > 99 && i < 999 {
				t.Error("Test fail: legal OCRA dataInput session format:", str, "wasn't accpeted, error:", err)
			}
		}
	}
}

func Test_OCRADataInputTimeStamp(t *testing.T) {
	ocraTimeStampFmt := []string{"OCRA-1:HOTP-SHA1-6:QN10-%v%v%v", "OCRA-1:HOTP-SHA1-6:C-QA10-%v%v%v", "OCRA-1:HOTP-SHA1-6:C-QA10-%v%v%v-S064"}
	key := "12345678"
	question := "1234112233"

	for _, s := range ocraTimeStampFmt {
		for i := ' '; i <= '}'; i++ {
			format := string(i) // strconv.Itoa(i)
			for j := 0; j < 200; j++ {
				str := strings.ToLower(fmt.Sprintf(s, "T", j, format))
				_, err := GenerateOCRAAdvance(str, key, "", question, "", "", "")
				lFormat := strings.ToLower(format)
				idx := strings.IndexAny(lFormat, ocraSuiteDataInputTimeStampTypeOptions)
				if err == nil && (idx == -1 || ((lFormat == "s" || lFormat == "m") && (j == 0 || j > 59)) || (lFormat == "h" && j > 48)) {
					t.Error("Test fail: Accept illegal OCRA dataInput timeStamp format:", str)
				}
				if err != nil && idx != -1 && (((lFormat == "s" || lFormat == "m") && j > 0 && j < 60) || (lFormat == "h" && j < 49)) {
					t.Error("Test fail: legal OCRA dataInput timeSTamp format:", str, "wasn't accpeted, error:", err, "idx:", idx)
				}
			}
		}
	}
}

func Test_OCRADataInput1(t *testing.T) {
	ocraSuite := "OCRA-1:HOTP-SHA1-6:QN08"
	seed := "3132333435363738393031323334353637383930"
	var data = []ocraTestS{{"00000000", "237653"}, {"11111111", "243178"}, {"22222222", "653583"},
		{"33333333", "740991"}, {"44444444", "608993"}, {"55555555", "388898"},
		{"66666666", "816933"}, {"77777777", "224598"}, {"88888888", "750600"},
		{"99999999", "294470"}}
	counter := ""
	password := ""
	session := ""
	timeStamp := ""

	for _, d := range data {
		ocra, err := GenerateOCRAAdvance(ocraSuite, seed, counter, d.question, password, session, timeStamp)
		if err != nil {
			t.Error("Test fail: Can't generate OCRA for:", ocraSuite, ", question:", d.question, ", error:", err)
		} else if ocra != d.exp {
			t.Error("Test fail: The generated OCRA:", ocra, " for:", ocraSuite, ", question:", d.question, " is not as expected:", d.exp)
		}
	}
}

func Test_OCRADataInput3(t *testing.T) {
	ocraSuite := "OCRA-1:HOTP-SHA256-8:QN08-PSHA1"
	seed32 := "31323334353637383930313233343536373839" + "30313233343536373839303132"
	pass := "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
	var data = []ocraTestS{{"00000000", "83238735"}, {"11111111", "01501458"}, {"22222222", "17957585"},
		{"33333333", "86776967"}, {"44444444", "86807031"}}
	counter := ""
	session := ""
	timeStamp := ""

	for _, d := range data {
		ocra, err := GenerateOCRAAdvance(ocraSuite, seed32, counter, d.question, pass, session, timeStamp)
		if err != nil {
			t.Error("Test fail: Can't generate OCRA for:", ocraSuite, ", question:", d.question, ", error:", err)
		} else if ocra != d.exp {
			t.Error("Test fail: The generated OCRA:", ocra, " for:", ocraSuite, ", question:", d.question, ", password:", pass, " is not as expected:", d.exp)
		}
	}
}

func Test_OCRADataInput4(t *testing.T) {
	ocraSuite := "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1"
	seed32 := "31323334353637383930313233343536373839" + "30313233343536373839303132"
	pass := "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
	var data = []ocraTestS{{"12345678", "65347737"}, {"12345678", "86775851"}, {"12345678", "78192410"},
		{"12345678", "71565254"}, {"12345678", "10104329"}, {"12345678", "65983500"},
		{"12345678", "70069104"}, {"12345678", "91771096"}, {"12345678", "75011558"},
		{"12345678", "08522129"}}
	session := ""
	timeStamp := ""

	for i, d := range data {
		counter := strconv.Itoa(i)
		ocra, err := GenerateOCRAAdvance(ocraSuite, seed32, counter, d.question, pass, session, timeStamp)
		if err != nil {
			t.Error("Test fail: Can't generate OCRA for:", ocraSuite, ", question:", d.question, ", error:", err)
		} else if ocra != d.exp {
			t.Error("Test fail: The generated OCRA:", ocra, " for:", ocraSuite, ", question:", d.question, ", password:", pass, ", counter:", counter, " is not as expected:", d.exp)
		}
	}
}

func Test_OCRADataInput5(t *testing.T) {
	ocraSuite := "OCRA-1:HOTP-SHA512-8:C-QN08"
	seed64 := "31323334353637383930313233343536373839" + "3031323334353637383930313233343536373839" +
		"3031323334353637383930313233343536373839" + "3031323334"
	var data = []ocraTestS{{"00000000", "07016083"}, {"11111111", "63947962"}, {"22222222", "70123924"},
		{"33333333", "25341727"}, {"44444444", "33203315"}, {"55555555", "34205738"},
		{"66666666", "44343969"}, {"77777777", "51946085"}, {"88888888", "20403879"},
		{"99999999", "31409299"}}
	pass := ""
	session := ""
	timeStamp := ""

	for i, d := range data {
		counter := "0000" + strconv.Itoa(i)
		ocra, err := GenerateOCRAAdvance(ocraSuite, seed64, counter, d.question, pass, session, timeStamp)
		if err != nil {
			t.Error("Test fail: Can't generate OCRA for:", ocraSuite, ", question:", d.question, ", error:", err)
		} else if ocra != d.exp {
			t.Error("Test fail: The generated OCRA:", ocra, " for:", ocraSuite, ", question:", d.question, ", counter:", counter, " is not as expected:", d.exp)
		}
	}
}

func Test_OCRADataInput6(t *testing.T) {
	ocraSuite := "OCRA-1:HOTP-SHA512-8:QN08-T1M"
	seed64 := "31323334353637383930313233343536373839" + "3031323334353637383930313233343536373839" +
		"3031323334353637383930313233343536373839" + "3031323334"
	timeStamp := "132d0b6"
	pass := ""
	session := ""

	var data = []ocraTestS{{"00000000", "95209754"}, {"11111111", "55907591"}, {"22222222", "22048402"},
		{"33333333", "24218844"}, {"44444444", "36209546"}}

	for i, d := range data {
		counter := "0000" + strconv.Itoa(i)
		ocra, err := GenerateOCRAAdvance(ocraSuite, seed64, counter, d.question, pass, session, timeStamp)
		if err != nil {
			t.Error("Test fail: Can't generate OCRA for:", ocraSuite, ", question:", d.question, ", error:", err)
		} else if ocra != d.exp {
			t.Error("Test fail: The generated OCRA:", ocra, " for:", ocraSuite, ", question:", d.question, ", timeStamp:", timeStamp, " is not as expected:", d.exp)
		}
	}
}

func Test_OCRADataInput7(t *testing.T) {
	ocraSuite := "OCRA-1:HOTP-SHA256-8:QA08"
	seed32 := "31323334353637383930313233343536373839" + "30313233343536373839303132"
	counter := ""
	pass := ""
	session := ""
	timeStamp := ""

	var data = []ocraTestS{{"CLI22220SRV11110", "28247970"}, {"CLI22221SRV11111", "01984843"},
		{"CLI22222SRV11112", "65387857"}, {"CLI22223SRV11113", "03351211"}, {"CLI22224SRV11114", "83412541"}}

	for _, d := range data {
		ocra, err := GenerateOCRAAdvance(ocraSuite, seed32, counter, d.question, pass, session, timeStamp)
		if err != nil {
			t.Error("Test fail: Can't generate OCRA for:", ocraSuite, ", question:", d.question, ", error:", err)
		} else if ocra != d.exp {
			t.Error("Test fail: The generated OCRA:", ocra, " for:", ocraSuite, ", question:", d.question, " is not as expected:", d.exp)
		}
	}
}

// Note the expected data was not taken from the RFC but was generated by running the ref code from the RFC
func Test_OCRADataInput8(t *testing.T) {
	ocraSuite := "OCRA-1:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256"
	seed64 := "31323334353637383930313233343536373839" + "3031323334353637383930313233343536373839" +
		"3031323334353637383930313233343536373839" + "3031323334"

	var data = []ocraTestS{{"a0000000", "56733040"}, {"a1111111", "00194456"}, {"a2222222", "12083787"},
		{"a3333333", "43905546"}, {"a4444444", "81064535"}}

	for i, d := range data {
		counter := "96" + strconv.Itoa(i)
		session := "abc123" + strconv.Itoa(i)
		timeStamp := "132d0b6" + strconv.Itoa(i)
		pass := d.question + counter + session + timeStamp + d.question + timeStamp
		ocra, err := GenerateOCRAAdvance(ocraSuite, seed64, counter, d.question, pass, session, timeStamp)
		if err != nil {
			t.Error("Test fail: Can't generate OCRA for:", ocraSuite, ", question:", d.question, ", error:", err)
		} else if ocra != d.exp {
			t.Error("Test fail: The generated OCRA:", ocra, " for:", ocraSuite, ", question:", d.question, ", timeStamp:", timeStamp, " is not as expected:", d.exp)
		}
	}
}

// Verify that we recieved an errors when:
// 1. OCRA suite doesn't contain any question
// 2. Counter (C) is in the string but not as the first parameter (at the midddle or at the end) or have any value
// 3. Unknown parameter (e.g. -hapoel) is found
// 4. Valid OCRA parameter set twice
func Test_OCRAOcraSuiteErrors(t *testing.T) {
	ocraSuiteErrorsFmt := []string{"OCRA-1:HOTP-SHA512-8:QH08-%v-T1M", "OCRA-1:HOTP-SHA512-8:QH08-%v"}
	ocraSuiteNoQuestionErrorsFmt := []string{"OCRA-1:HOTP-SHA512-8:C-%v", "OCRA-1:HOTP-SHA512-8:%v", "OCRA-1:HOTP-SHA512-8:C%v-QH08"}
	ocraSuiteErrorsSetTwiceFmt := []string{"OCRA-1:HOTP-SHA512-8:%v-QH08-%v"}
	seed := "3132333435363738393031323334353637383930"
	tokens := []string{"T1M", "S064", "PSHA256"}
	allTokens := []string{"QN08", "T1M", "S064", "PSHA256"}

	for _, f := range ocraSuiteNoQuestionErrorsFmt {
		for _, token := range tokens {
			ocraSuite := fmt.Sprintf(f, token)
			_, err := GenerateOCRAAdvance(ocraSuite, seed, "1234", "1122334456", "1234", "1", "2")
			if err == nil {
				t.Error("Test fail: OCRA code was generated for invalid OCRA suite (does not contain any question):", ocraSuite)
			}
		}
	}

	for _, f := range ocraSuiteErrorsFmt {
		for c := ' '; c <= '}'; c++ {
			ocraSuite := fmt.Sprintf(f, string(c))
			_, err := GenerateOCRAAdvance(ocraSuite, seed, "1234", "1122334456", "1234", "1", "2")
			if err == nil {
				t.Error("Test fail: OCRA code was generated for invalid OCRA suite:", ocraSuite)
			}
		}
	}

	for _, f := range ocraSuiteErrorsSetTwiceFmt {
		for _, token := range allTokens {
			ocraSuite := fmt.Sprintf(f, token, token)
			_, err := GenerateOCRAAdvance(ocraSuite, seed, "1234", "1122334456", "1234", "1", "2")
			if err == nil {
				t.Error("Test fail: OCRA code was generated for invalid OCRA suite (the same parameter used more than once):", ocraSuite)
			}
		}
	}
}

//
func Test_UpdateOCRAData(t *testing.T) {
	testData := []ocraTestDataS{
		{UserOcra{"OCRA-1:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256", []byte("12345678")}, true},
		{UserOcra{"OCRA-3:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256", []byte("12345678")}, false},
		{UserOcra{"OCRA-1:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256", []byte("1234")}, false},
		{UserOcra{"", []byte("12345678")}, false},
		{UserOcra{"", []byte("")}, false},
	}

	for _, data := range testData {
		_, err := NewOcraUser(data.ocra.Key, data.ocra.OcraSuite)
		if err != nil && data.expected == true {
			t.Errorf("Test fail: Initialized OCRA with good parameters failed: Valid OCRA data parameters: OCRA Suite: '%v', key '%v', error: %v", data.ocra.OcraSuite, data.ocra.Key, err)
		} else if err == nil && data.expected == false {
			t.Errorf("Test fail: Succesfully initialized OCRA data with wrong parameters: OCRA Suite: '%v', key '%v'", data.ocra.OcraSuite, data.ocra.Key)
		}
	}
}

func Test_StoreLoad(t *testing.T) {
	secret := []byte("12345678")
	ocraSuite := "OCRA-1:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256"

	userOcra, err := NewOcraUser(secret, ocraSuite)
	err = userOcra.UpdateOcraKey(secret)
	if err != nil {
		t.Errorf("Fatal error: OCRA key couldn't be updated, error: %v", err)
	}
	err = userOcra.UpdateOcraSuite(ocraSuite)
	if err != nil {
		t.Errorf("Fatal error: OCRA suite couldn't be updated, error: %v", err)
	}

	defs.StoreLoadTest(t, userOcra, defs.OcraPropertyName)
}	
