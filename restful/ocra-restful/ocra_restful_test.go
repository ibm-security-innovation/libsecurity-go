package ocraRestful

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/emicklei/go-restful"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	"github.com/ibm-security-innovation/libsecurity-go/ocra"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
)

const (
	host     = "http://localhost"
	port     = ":8082"
	listener = host + port

	userName1 = "User1"
	userName2 = "User2"

	internalOcraSuite = "OCRA-1:HOTP-SHA1-6:QA08"

	secretCode    = "12345678"
)

var (
	propertyName = defs.OcraPropertyName
	uData, _     = json.Marshal(ocraUserData{secretCode, internalOcraSuite})

	resourcePath     string // = listener + servicePath + usersPath
	usersName        = []string{userName1, userName2}
	ocraUserDataInfo = ocraUserData{secretCode, internalOcraSuite}

	stRestful *libsecurityRestful.LibsecurityRestful
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	servicePath = cr.ServicePathPrefix + cr.Version + ocraPrefix
	resourcePath = listener + servicePath + usersPath

	usersList := en.New()

	stRestful = libsecurityRestful.NewLibsecurityRestful()
	stRestful.SetData(usersList, nil, nil, nil, nil)
	stRestful.SetToFilterFlag(false)

	for _, name := range usersName {
		stRestful.UsersList.AddUser(name)
	}

	go runServer()
	time.Sleep(100 * time.Millisecond)
}

func runServer() {
	wsContainer := restful.NewContainer()

	o := NewOcraRestful()
	o.SetData(stRestful)
	o.RegisterBasic(wsContainer)

	log.Printf("start listening on %v%v", host, port)
	server := &http.Server{Addr: port, Handler: wsContainer}
	log.Fatal(server.ListenAndServe())
}

func getExpectedData(sData string, okJ interface{}) (string, string, cr.Error, error) {
	found, exp, res, e, err := cr.GetExpectedData(sData, okJ)
	if found == true {
		return exp, res, e, err
	}
	switch okJ.(type) {
	case *ocra.UserOcra:
		var user ocra.UserOcra
		json.Unmarshal([]byte(sData), &user)
		data, _ := json.Marshal(user)
		res = string(data)
		data, _ = json.Marshal(okJ.(*ocra.UserOcra))
		exp = string(data)
	case *ocraData:
		var oData ocraData
		json.Unmarshal([]byte(sData), &oData)
		data, _ := json.Marshal(oData)
		res = string(data)
		data, _ = json.Marshal(okJ.(*ocraData))
		exp = string(data)
	default:
		panic(fmt.Sprintf("Error unknown type: value: %v", okJ))
	}

	if err != nil {
		err = json.Unmarshal([]byte(sData), &e)
	}
	return exp, res, e, err
}

func exeCommandCheckRes(t *testing.T, method string, url string, expCode int, data string, okJ interface{}) string {
	code, sData, err := cr.HTTPDataMethod(method, url, data)
	logger.Info.Printf("Method: %v, Url: %v, data: '%v', response code: %v, response data: '%v', error: %v\n",
		method, url, data, code, sData, err)
	exp, res, e, err := getExpectedData(sData, okJ)
	if code != expCode || res != exp || err != nil {
		t.Errorf("Test fail: run %v '%v' Expected status: %v, received %v, expected data: '%v' received: '%v', error: %v %v",
			method, url, expCode, code, exp, res, e, err)
		t.FailNow()
	}
	return res
}

func initAListOfUsers(t *testing.T, usersList []string) string {
	for _, name := range usersList {
		okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
		url := resourcePath + "/" + name
		exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusCreated, string(uData), okURLJ)
		data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", data.(*ocra.UserOcra))
	}
	return string(uData)
}

// Add Ocra property and get it
// Remove the propert and verify an error when try to get it
func Test_addRemoveOcra(t *testing.T) {
	name := usersName[0]
	initAListOfUsers(t, usersName)
	okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
	url := resourcePath + "/" + name
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusCreated, string(uData), okURLJ)
	data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", data.(*ocra.UserOcra))

	okURLJ = cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
	url = resourcePath + "/" + name
	exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})

	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusNotFound, "", cr.Error{Code: http.StatusNotFound})
}

// Check that an update key is working as expected
func TestVerifyUpdateKey(t *testing.T) {
	userName := usersName[0]
	newSecret := secretCode + "aa"

	initAListOfUsers(t, usersName)
	url := listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserUpdateCommand]), usersPath, userName, keyToken)
	okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, userName)}
	secret, _ := json.Marshal(cr.Secret{Secret: newSecret})
	exeCommandCheckRes(t, cr.HTTPPatchStr, url, http.StatusCreated, string(secret), okURLJ)

	OcraData, _ := ocra.NewOcraUser([]byte(newSecret), internalOcraSuite)
	url = resourcePath + "/" + userName
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", OcraData)
}

// 2. Check that an update ocraSuite is working as expected
func TestVerifyUpdateOcraSuite(t *testing.T) {
	userName := usersName[0]
	newOcra := "OCRA-1:HOTP-SHA512-8:C-QH08-T1M-S064-PSHA256"

	initAListOfUsers(t, usersName)

	url := listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserUpdateCommand]), usersPath, userName, ocraSuiteToken)
	okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, userName)}
	str, _ := json.Marshal(cr.StringMessage{Str: newOcra})
	exeCommandCheckRes(t, cr.HTTPPatchStr, url, http.StatusCreated, string(str), okURLJ)

	OcraData, _ := ocra.NewOcraUser([]byte(secretCode), newOcra)
	url = resourcePath + "/" + userName
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", OcraData)
}

func TestOneWayChallengeResponse(t *testing.T) {
	userName := usersName[0]

	initAListOfUsers(t, usersName)

	url := listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserIdentityCommand]), usersPath, userName, verifyUserIdentityChallengeToken)
	res := exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", cr.StringMessage{Str: cr.GetMessageStr})
	var OcraData ocraData
	err := json.Unmarshal([]byte(res), &OcraData)
	if err != nil {
		t.Errorf("Test fail: execute GET to '%v' expected to get ocra data but received: %v, error: %v",
			url, res, err)
	}
	//Calculate the cleint OTP
	otp, err := ocra.GenerateOCRAAdvance(ocraUserDataInfo.OcraSuite, secretCode,
		OcraData.Counter, OcraData.ServerQuestion, OcraData.Password, OcraData.SessionID, OcraData.TimeStamp)
	logger.Info.Println("The calculated OTP for ocra data:", res, "is:", otp)
	if err != nil {
		t.Errorf("Test fail: Try to generate OCRA with the following parameters: %v, error: %v", res, err)
	}
	OcraData.Otp = otp
	data, _ := json.Marshal(OcraData)
	url = listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserIdentityCommand]), usersPath, userName, verifyUserIdentityOtpToken)
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusOK, string(data), cr.Match{Match: true, Message: ""})
}

func TestMutualChallengeResponse(t *testing.T) {
	var OcraData ocraData
	userName := usersName[0]

	initAListOfUsers(t, usersName)

	OcraData.ClientQuestion = "The client 1"
	url := listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserIdentityCommand]), usersPath, userName, verifyUserIdentityMutualChallengeStep1Token)
	data, _ := json.Marshal(cr.StringMessage{Str: OcraData.ClientQuestion})
	res := exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusOK, string(data), cr.StringMessage{Str: cr.GetMessageStr})
	err := json.Unmarshal([]byte(res), &OcraData)
	if err != nil {
		t.Errorf("Test fail: execute GET to '%v' expected to get ocra data but received: %v, error: %v",
			url, res, err)
		t.FailNow()
	}
	clientOtp, err := ocra.GenerateOCRAAdvance(ocraUserDataInfo.OcraSuite, secretCode,
		OcraData.Counter, OcraData.ServerQuestion+OcraData.ClientQuestion, OcraData.Password, OcraData.SessionID, OcraData.TimeStamp)
	serverOtp, _ := ocra.GenerateOCRAAdvance(ocraUserDataInfo.OcraSuite, secretCode,
		OcraData.Counter, OcraData.ClientQuestion+OcraData.ServerQuestion, OcraData.Password, OcraData.SessionID, OcraData.TimeStamp)
	logger.Info.Println("The calculated client OTP for ocra data:", res, "and client question:", OcraData.ClientQuestion, "is:", clientOtp, "the server otp:", serverOtp)
	if err != nil {
		t.Errorf("Test fail: Try to generate OCRA with the following parameters: %v, error: %v", res, err)
		t.FailNow()
	}

	if OcraData.Otp != serverOtp {
		t.Errorf("Test fail: The calculated server OTP: %v is not as the received OTP: %v", serverOtp, OcraData.Otp)
		t.FailNow()
	}

	url = listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserIdentityCommand]), usersPath, userName, verifyUserIdentityMutualChallengeStep2Token)
	OcraData.Otp = clientOtp
	data, _ = json.Marshal(OcraData)
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusOK, string(data), cr.Match{Match: true, Message: ""})
}
