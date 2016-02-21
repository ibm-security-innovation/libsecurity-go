package otpRestful

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
	"github.com/ibm-security-innovation/libsecurity-go/otp"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
)

const (
	host     = "http://localhost"
	port     = ":8082"
	listener = host + port

	userName1 = "User1"
	userName2 = "User2"

	secretCode = "A1b2@345678"
	emptyRes   = "{}"
)

var (
	propertyName = defs.OtpPropertyName
	resourcePath string // = listener + servicePath + usersPath
	usersName    = []string{userName1, userName2}

	uData, _ = json.Marshal(cr.Secret{Secret: secretCode})

	stRestful *libsecurityRestful.LibsecurityRestful
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	servicePath = cr.ServicePathPrefix + cr.Version + otpPrefix
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

	o := NewOtpRestful()
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
	case *otp.UserInfoOtp:
		var user otp.UserInfoOtp
		json.Unmarshal([]byte(sData), &user)
		data, _ := json.Marshal(user)
		res = string(data)
		data, _ = json.Marshal(okJ.(*otp.UserInfoOtp))
		exp = string(data)
	case userState:
		var state userState
		err = json.Unmarshal([]byte(sData), &state)
		res = fmt.Sprintf("%v", state.Blocked)
		exp = fmt.Sprintf("%v", okJ.(userState).Blocked)
	default:
		panic(fmt.Sprintf("Error unknown type: %v", okJ))
	}

	if err != nil {
		err = json.Unmarshal([]byte(sData), &e)
	}
	return exp, res, e, err
}

func exeCommandCheckRes(t *testing.T, method string, url string, expCode int, data string, okJ interface{}) {
	code, sData, _ := cr.HTTPDataMethod(method, url, data)
	exp, res, e, err := getExpectedData(sData, okJ)
	if code != expCode || res != exp || err != nil {
		t.Errorf("Test fail: run %v '%v' Expected status: %v, received %v, expected data: '%v' received: '%v', error: %v %v",
			method, url, expCode, code, exp, res, e, err)
		t.FailNow()
	}
}

func initAListOfUsers(t *testing.T, usersList []string) string {
	for _, name := range usersList {
		okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
		url := resourcePath + "/" + name
		exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusCreated, string(uData), okURLJ)
		data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", data.(*otp.UserInfoOtp))
	}
	return string(uData)
}

// Add OTP property and get it
// Remove the propert and verify an error when try to get it
func Test_addRemoveOtp(t *testing.T) {
	name := usersName[0]
	initAListOfUsers(t, usersName)

	okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
	url := resourcePath + "/" + name
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusCreated, string(uData), okURLJ)

	data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", data.(*otp.UserInfoOtp))

	okURLJ = cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
	url = resourcePath + "/" + name
	exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})

	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusNotFound, "", cr.Error{Code: http.StatusNotFound})
}

// Set User blocked to true, false, true and verify the status
func TestSetUserBlockedState(t *testing.T) {
	userName := usersName[0]
	states := []bool{true, false, true}

	initAListOfUsers(t, usersName)

	for _, val := range states {
		data, _ := json.Marshal(userState{val})
		url := listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserBlockCommand]), usersPath, userName, blockedStateToken)
		okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, userName)}
		exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusOK, string(data), okURLJ) // fix the statusOK
		url = listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserBlockCommand]), usersPath, userName, blockedStateToken)
		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", userState{val})
	}
}

// 1. Check with match OTP code using HOTP/TOTP, verify the results
// 2. Check with not matched code using HOTP/TOTP, verify the results
func TestVerifyHotpCode(t *testing.T) {
	var exp string
	userName := usersName[0]

	initAListOfUsers(t, usersName)

	secret, _ := json.Marshal(cr.Secret{Secret: secretCode})
	url := resourcePath + "/" + userName
	okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, userName)}
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusCreated, string(secret), okURLJ) // TODO fix it
	user, _ := otp.NewSimpleOtpUser([]byte(secretCode), false)

	for i := 0; i < 2; i++ {
		if i == 0 { // HOTP
			exp, _ = user.BaseHotp.AtCount(user.BaseHotp.Count)
			url = listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserCodeCommand]), usersPath, userName, verifyHotpTypeParam)
		} else {
			exp, _ = user.BaseTotp.Now()
			url = listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserCodeCommand]), usersPath, userName, verifyTotpTypeParam)
		}
		secret, _ = json.Marshal(cr.Secret{Secret: exp})
		exeCommandCheckRes(t, cr.HTTPPostStr, url, http.StatusOK, string(secret), cr.Match{Match: true, Message: cr.NoMessageStr})
		// The same code can't be used twice
		exeCommandCheckRes(t, cr.HTTPPostStr, url, http.StatusOK, string(secret), cr.Match{Match: false, Message: cr.NoMessageStr})
	}
}

// Verify errors for the following secenarios:
// 1. Verify that simple password is not accepted
// 2. Verify that wrong parameter as password is not accepted
// 3. Verify that put new OPT to undefined user return with error
// 4. Verify that delete OPT from undefined user return with error
// 5. Verify that get block status from undefined user return with error
// 6. Verify that put block status to undefined user return with error
func TestErrors(t *testing.T) {
	data, _ := json.Marshal(cr.Secret{Secret: "123"})
	sData, _ := json.Marshal(userState{true})

	url := listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserCommand]), usersPath, usersName[0])
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusBadRequest, string(data), cr.Match{Match: false, Message: cr.NoMessageStr})
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusBadRequest, string(sData), cr.Match{Match: false, Message: cr.NoMessageStr})
	url = listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserCommand]), usersPath, "undef user")
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusNotFound, string(uData), cr.Match{Match: false, Message: cr.NoMessageStr})
	exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNotFound, string(uData), cr.Match{Match: false, Message: cr.NoMessageStr})

	url = listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserBlockCommand]), usersPath, "undef user", blockedStateToken)
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusNotFound, string(sData), cr.Match{Match: false, Message: cr.NoMessageStr})
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusNotFound, string(sData), cr.Match{Match: false, Message: cr.NoMessageStr})

	// use the wrong object return with error: it is not checked by golang, if it is critical, unmarshal to map and verify the relevant fields can be used
	//	initAListOfUsers(t, usersName)
	//	url = listener + servicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserBlockCommand]), usersPath, usersName[0], blockedStateToken)
	//	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusBadRequest, string(uData), cr.Match{Match: false, Message: cr.NoMessageStr})
}