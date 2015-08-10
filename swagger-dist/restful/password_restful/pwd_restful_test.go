package password_restful

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/emicklei/go-restful"
	stc "ibm-security-innovation/libsecurity-go/defs"
	en "ibm-security-innovation/libsecurity-go/entity"
	logger "ibm-security-innovation/libsecurity-go/logger"
	"ibm-security-innovation/libsecurity-go/password"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	host     = "http://localhost"
	port     = ":8082"
	listener = host + port

	userName1 = "User1"
	userName2 = "User2"

	secretCode    = "12345678"
	getMessageStr = "get-data"
)

var (
	propertyName = stc.PwdPropertyName
	uData, _     = json.Marshal(secretData{secretCode})

	resourcePath string // = listener + ServicePath + UsersPath
	usersName    = []string{userName1, userName2}

	stRestful *libsecurity_restful.LibsecurityRestful
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	ServicePath = cr.ServicePathPrefix + cr.Version + PwdPrefix
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
	p := NewPwdRestful()
	p.SetData(stRestful)
	p.RegisterBasic(wsContainer)

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
	case *password.UserPwd: // expiration time is not compared
		res = cr.RemoveSpaces(string(sData))
		var user password.UserPwd
		json.Unmarshal([]byte(sData), &user)
		user.Expiration = okJ.(*password.UserPwd).Expiration
		if reflect.DeepEqual(user, okJ.(*password.UserPwd)) == false {
			data, _ := json.Marshal(okJ.(*password.UserPwd))
			exp = string(data)
		} else {
			exp = res
		}
	default:
		panic(fmt.Sprintf("Error unknown type: value: %v", okJ))
	}

	if err != nil {
		err = json.Unmarshal([]byte(sData), &e)
	}
	return exp, res, e, err
}

func exeCommandCheckRes(t *testing.T, method string, url string, expCode int, data string, okJ interface{}) string {
	code, sData, err := cr.HttpDataMethod(method, url, data)
	logger.Trace.Println("Method:", method, "Url:", url, "data:", data, "response code:", code, "response data:", sData, "error:", err)
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
		okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
		url := resourcePath + "/" + name
		exeCommandCheckRes(t, cr.PUT_STR, url, http.StatusCreated, string(uData), okUrlJ)
		data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
		exeCommandCheckRes(t, cr.GET_STR, url, http.StatusOK, "", data.(*password.UserPwd))
	}
	return string(uData)
}

// Add Ocra property and get it
// Remove the propert and verify an error when try to get it
func Test_addRemoveOcra(t *testing.T) {
	name := usersName[0]
	initAListOfUsers(t, usersName)

	okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
	url := resourcePath + "/" + name
	exeCommandCheckRes(t, cr.PUT_STR, url, http.StatusCreated, string(uData), okUrlJ)

	data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
	exeCommandCheckRes(t, cr.GET_STR, url, http.StatusOK, "", data.(*password.UserPwd))

	okUrlJ = cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
	url = resourcePath + "/" + name
	exeCommandCheckRes(t, cr.DELETE_STR, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})

	exeCommandCheckRes(t, cr.GET_STR, url, http.StatusNotFound, "", cr.Error{Code: http.StatusNotFound})
}

// 1. Check with match password, verify the results
// 2. Check with not matched password, verify the results
// 3. Update user password and verify that the new password matched
// 4. Verify that the old password not matched
func TestVerifyPassword(t *testing.T) {
	userName := usersName[0]

	secret := initAListOfUsers(t, usersName)

	url := listener + ServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserPasswordCommand]), UsersPath, userName)
	okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, userName)}
	exeCommandCheckRes(t, cr.POST_STR, url, http.StatusOK, secret, cr.Match{Match: true, Message: cr.NoMessageStr})

	secret1, _ := json.Marshal(secretData{secretCode + "a"})
	exeCommandCheckRes(t, cr.POST_STR, url, http.StatusOK, string(secret1), cr.Match{Match: false, Message: cr.NoMessageStr})

	secret2, _ := json.Marshal(cr.UpdateSecret{OldPassword: secretCode, NewPassword: secretCode + "a"})
	exeCommandCheckRes(t, cr.PATCH_STR, url, http.StatusCreated, string(secret2), okUrlJ)
	exeCommandCheckRes(t, cr.POST_STR, url, http.StatusOK, string(secret1), cr.Match{Match: true, Message: cr.NoMessageStr})
	exeCommandCheckRes(t, cr.POST_STR, url, http.StatusOK, secret, cr.Match{Match: false, Message: cr.NoMessageStr})
}

// 2. Reset the user password
// 3. Check that the new password match only once
// 4. Update user password and verify that the new password matched
func TestVerifyResetPassword(t *testing.T) {
	userName := usersName[0]

	initAListOfUsers(t, usersName)

	url := listener + ServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[resetUserPasswordCommand]), UsersPath, userName, ResetUserPwdPath)
	secretStr := exeCommandCheckRes(t, cr.GET_STR, url, http.StatusCreated, getMessageStr, cr.StringMessage{Str: getMessageStr})

	url = listener + ServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[verifyUserPasswordCommand]), UsersPath, userName)
	exeCommandCheckRes(t, cr.POST_STR, url, http.StatusOK, secretStr, cr.Match{Match: true, Message: cr.NoMessageStr})

	secret1, _ := json.Marshal(secretData{secretCode})
	exeCommandCheckRes(t, cr.POST_STR, url, http.StatusOK, string(secret1), cr.Match{Match: false, Message: cr.NoMessageStr})
}
