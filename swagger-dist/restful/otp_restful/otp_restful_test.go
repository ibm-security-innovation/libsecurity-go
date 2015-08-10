package otp_restful

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/emicklei/go-restful"
	stc "ibm-security-innovation/libsecurity-go/defs"
	en "ibm-security-innovation/libsecurity-go/entity"
	logger "ibm-security-innovation/libsecurity-go/logger"
	"ibm-security-innovation/libsecurity-go/otp"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	host     = "http://localhost"
	port     = ":8082"
	listener = host + port

	userName1 = "User1"
	userName2 = "User2"

	secretCode = "12345678"
	emptyRes   = "{}"
)

var (
	propertyName = stc.OtpPropertyName
	resourcePath string // = listener + ServicePath + UsersPath
	usersName    = []string{userName1, userName2}

	uData, _ = json.Marshal(cr.Secret{Secret: secretCode})

	stRestful *libsecurity_restful.LibsecurityRestful
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	ServicePath = cr.ServicePathPrefix + cr.Version + OtpPrefix
	resourcePath = listener + ServicePath + UsersPath

	usersList := en.NewEntityManager()

	stRestful = libsecurity_restful.NewLibsecurityRestful()
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
	case *otp.OtpUser:
		var user otp.OtpUser
		json.Unmarshal([]byte(sData), &user)
		data, _ := json.Marshal(user)
		res = string(data)
		data, _ = json.Marshal(okJ.(*otp.OtpUser))
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
	code, sData, _ := cr.HttpDataMethod(method, url, data)
	exp, res, e, err := getExpectedData(sData, okJ)
	if code != expCode || res != exp || err != nil {
		t.Errorf("Test fail: run %v '%v' Expected status: %v, received %v, expected data: '%v' received: '%v', error: %v %v",
			method, url, expCode, code, exp, res, e, err)
		t.FailNow()
	}
}

func initAListOfUsers(t *testing.T, usersList []string) string {
	for _, name := range usersList {
		okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
		url := resourcePath + "/" + name
		exeCommandCheckRes(t, cr.PUT_STR, url, http.StatusCreated, string(uData), okUrlJ)
		data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
		exeCommandCheckRes(t, cr.GET_STR, url, http.StatusOK, "", data.(*otp.OtpUser))
	}
	return string(uData)
}

// Add OTP property and get it
// Remove the propert and verify an error when try to get it
func Test_addRemoveOtp(t *testing.T) {
	name := usersName[0]
	initAListOfUsers(t, usersName)

	okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
	url := resourcePath + "/" + name
	exeCommandCheckRes(t, cr.PUT_STR, url, http.StatusCreated, string(uData), okUrlJ)

	data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
	exeCommandCheckRes(t, cr.GET_STR, url, http.StatusOK, "", data.(*otp.OtpUser))

	okUrlJ = cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
	url = resourcePath + "/" + name
	exeCommandCheckRes(t, cr.DELETE_STR, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})

	exeCommandCheckRes(t, cr.GET_STR, url, http.StatusNotFound, "", cr.Error{Code: http.StatusNotFound})
}

// Set User blocked to true, false, true and verify the status
func TestSetUserBlockedState(t *testing.T) {
	userName := usersName[0]
	states := []bool{true, false, true}

	initAListOfUsers(t, usersName)

	for _, val := range states {
		data, _ := json.Marshal(userState{val})
		url := listener + ServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserBlockCommand]), UsersPath, userName, blockedStateToken)
		okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, userName)}
		exeCommandCheckRes(t, cr.PUT_STR, url, http.StatusOK, string(data), okUrlJ) // fix the statusOK
		url = listener + ServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUserBlockCommand]), UsersPath, userName, blockedStateToken)
		exeCommandCheckRes(t, cr.GET_STR, url, http.StatusOK, "", userState{val})
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
	okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, userName)}
	exeCommandCheckRes(t, cr.PUT_STR, url, http.StatusCreated, string(secret), okUrlJ) // TODO fix it
	user, _ := otp.NewSimpleOtpUser([]byte(secretCode))

	for i := 0; i < 2; i++ {
		if i == 0 { // HOTP
			exp, _ = user.BaseHotp.AtCount(user.BaseHotp.Count)
			url = listener + ServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserCodeCommand]), UsersPath, userName, verifyHotpTypeParam)
		} else {
			exp, _ = user.BaseTotp.Now()
			url = listener + ServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserCodeCommand]), UsersPath, userName, verifyTotpTypeParam)
		}
		secret, _ = json.Marshal(cr.Secret{Secret: exp})
		exeCommandCheckRes(t, cr.POST_STR, url, http.StatusOK, string(secret), cr.Match{Match: true, Message: cr.NoMessageStr})
		// The same code can't be used twice
		exeCommandCheckRes(t, cr.POST_STR, url, http.StatusOK, string(secret), cr.Match{Match: false, Message: cr.NoMessageStr})
	}
}
