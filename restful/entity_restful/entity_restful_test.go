package entity_restful

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
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common_restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	host     = "http://localhost"
	port     = ":8082"
	listener = host + port

	userName1     = "User1"
	userName2     = "User2"
	groupName1    = "group1"
	resourceName1 = "Disk1"
	resourceName2 = "Camera1"

	emptyRes = "{}"

	protectedEntityManagerLen = 2 // set it if the EntityManager.protectedEntityManager is chaned
)

var (
	enResourcePath     string //     = listener + EnServicePath
	enUserResourcePath string //= listener + EnServicePath + UsersPath
	enPath             string

	usersName     = []string{userName1, userName2}
	resourcesName = []string{resourceName1, resourceName2}

	stRestful  *libsecurity_restful.LibsecurityRestful
	BasicUsers = en.New()
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	EnServicePath = cr.ServicePathPrefix + cr.Version + UmPrefix
	enResourcePath = listener + EnServicePath
	enUserResourcePath = listener + EnServicePath + UsersPath
	UsersServicePath = EnServicePath + UsersPath
	ResourceServicePath = EnServicePath + ResourcesPath
	enPath = listener + EnServicePath

	usersList := en.New()

	stRestful = libsecurity_restful.NewLibsecurityRestful()
	stRestful.SetData(usersList, nil, nil, nil, nil)
	stRestful.SetToFilterFlag(false)

	go runServer()
	time.Sleep(100 * time.Millisecond)
}

func runServer() {
	wsContainer := restful.NewContainer()
	um := NewEnRestful()
	um.SetData(stRestful)
	um.RegisterBasic(wsContainer)

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
	case en.EntityManager:
		res = cr.RemoveSpaces(string(sData))
		d1, _ := json.Marshal(okJ.(en.EntityManager))
		var us en.EntityManager
		json.Unmarshal([]byte(sData), &us)
		if reflect.DeepEqual(us, okJ.(en.EntityManager)) == false {
			exp = string(d1)
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

func generateEn() error {
	stRestful.UsersList.AddGroup(groupName1)
	for _, name := range usersName {
		stRestful.UsersList.AddUser(name)
		stRestful.UsersList.AddUserToGroup(groupName1, name)
	}
	return nil
}

func addDataVerifyResults(t *testing.T, userName string, url string, okJ cr.Url) {
	exeCommandCheckRes(t, cr.PUT_STR, url, http.StatusCreated, url, okJ)

	code, sData, _ := cr.HttpDataMethod(cr.GET_STR, enPath, "")
	var resData en.EntityManager
	json.Unmarshal([]byte(sData), &resData)
	if code != http.StatusOK || reflect.DeepEqual(stRestful.UsersList, &resData) == false {
		t.Errorf("Test fail: run GET '%v' Expected status: %v received %v, expected data: '%v' received '%v'",
			enPath, http.StatusOK, code, stRestful.UsersList, resData)
		t.FailNow()
	}
}

func verifyLen(t *testing.T, url string, lenType string, length int) {
	code, _, _ := cr.HttpDataMethod(cr.GET_STR, url, "")

	curentLen := len(stRestful.UsersList.Users)
	if lenType == ResourcesPath {
		curentLen = len(stRestful.UsersList.Resources)
	}
	if code != http.StatusOK || curentLen != length {
		t.Errorf("Test fail: run GET '%v' Expected status: %v recived %v, expected length: %v, received: %v",
			url, http.StatusOK, code, length, curentLen)
	}
}

func initState(t *testing.T) {
	// remove all users
	for _, user := range stRestful.UsersList.Users {
		exeCommandCheckRes(t, cr.DELETE_STR, enUserResourcePath, http.StatusNoContent, user.Name, cr.StringMessage{Str: ""})
	}
	// get all users: the structure must include the root user and all entries
	exeCommandCheckRes(t, cr.GET_STR, enPath, http.StatusOK, "", *BasicUsers)
	verifyLen(t, enPath, UsersPath, protectedEntityManagerLen)
}

// Initialize the UsersList to include all users from a given file
func setUm(t *testing.T, url string) {
	for i, name := range usersName {
		iUrl := url + EnServicePath
		okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", UsersServicePath, name)}
		specificUrl := iUrl + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmUserCommand]), name)
		addDataVerifyResults(t, name, specificUrl, okUrlJ)
		verifyLen(t, enPath, UsersPath, i+1+protectedEntityManagerLen)
	}
}

// Initialize the UsersList to include resource
func setResource(t *testing.T, url string) {
	for i, name := range resourcesName {
		iUrl := url + EnServicePath
		okUrlJ := cr.Url{Url: fmt.Sprintf("%v/%v", ResourceServicePath, name)}
		specificUrl := iUrl + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmResourceCommand]), name)
		addDataVerifyResults(t, name, specificUrl, okUrlJ)
		verifyLen(t, enPath, ResourcesPath, i+1)
	}
}

// Test the following:
// 1. The users list is empty
// 2. Add a new user, verify the response code and that there is only one user with the same content
// 4. Add a new user, verify the response code and that there are 2 users each with the extpected content
// 5. Remove the first user, verify the response code and that there is only one user, the second one
// 6. Remove the second user, verify the response code and that the user list is empty
func TestAddRemoveUser(t *testing.T) {
	initState(t)
	setUm(t, listener)
	// remove users and verify that the number of users decrease
	for i, name := range usersName {
		url := listener + UsersServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmCommand]), name)
		exeCommandCheckRes(t, cr.DELETE_STR, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})
		verifyLen(t, enPath, UsersPath, len(usersName)-i+1)
	}
}

// Test the following:
// 1. The users list is empty
// 2. Add a new resource, verify the response code and that there is only one resource with the same content
// 4. Add a new resource, verify the response code and that there are 2 resource each with the extpected content
// 5. Remove the first resource, verify the response code and that there is only one resource, the second one
// 6. Remove the second resource, verify the response code and that the resource list is empty
func TestAddRemoveResource(t *testing.T) {
	initState(t)
	setResource(t, listener)
	// remove resource and verify that the number of resource decrease
	for i, name := range resourcesName {
		url := listener + ResourceServicePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmCommand]), name)
		exeCommandCheckRes(t, cr.DELETE_STR, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})
		verifyLen(t, enPath, ResourcesPath, len(resourcesName)-i-1)
	}
}
