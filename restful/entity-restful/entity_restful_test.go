package entityRestful

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
	ent "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
)

const (
	host     = "http://localhost"
	port     = ":8082"
	listener = host + port

	userName1     = "User1"
	userName2     = "User2"
	groupName1    = "group1"
	groupName2    = "G-2"
	resourceName1 = "Disk1"
	resourceName2 = "Camera1"

	emptyRes = "{}"

	usersIdx = iota
    groupsIdx
    resourceIdx

	protectedEntityManagerLen = 2 // set it if the EntityManager.protectedEntityManager is chaned
)

var (
	enAllPath     	   string //     = listener + enServicePath
	enPath             string

	usersName     = []string{userName1, userName2}
	resourcesName = []string{resourceName1, resourceName2}
	groupsName = []string{groupName1, groupName2}

	servicePath = map[int]string {usersIdx: usersPath, groupsIdx: groupsPath, resourceIdx: resourcesPath}
	stRestful  *libsecurityRestful.LibsecurityRestful
	BasicUsers = ent.New()
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	enServicePath = cr.ServicePathPrefix + cr.Version + umPrefix
	enAllPath = listener + enServicePath
	enPath = listener + enServicePath

	usersList := ent.New()

	stRestful = libsecurityRestful.NewLibsecurityRestful()
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
	case ent.EntityManager:
		res = cr.RemoveSpaces(string(sData))
		d1, _ := json.Marshal(okJ.(ent.EntityManager))
		var us ent.EntityManager
		json.Unmarshal([]byte(sData), &us)
		if reflect.DeepEqual(us, okJ.(ent.EntityManager)) == false {
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

func generateEn() error {
	stRestful.UsersList.AddGroup(groupName1)
	for _, name := range usersName {
		stRestful.UsersList.AddUser(name)
		stRestful.UsersList.AddUserToGroup(groupName1, name)
	}
	return nil
}

func addDataVerifyResults(t *testing.T, url string, okJ cr.URL) {
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusCreated, url, okJ)

	code, sData, _ := cr.HTTPDataMethod(cr.HTTPGetStr, enPath, "")
	var resData ent.EntityManager
	json.Unmarshal([]byte(sData), &resData)
	// reflect can't be used because of the property reflect.DeepEqual(stRestful.UsersList, &resData) == false {
	if code != http.StatusOK || len(resData.Users) != len(stRestful.UsersList.Users) || len(resData.Groups) != len(stRestful.UsersList.Groups) ||
	 		len(resData.Resources) != len(stRestful.UsersList.Resources){
		t.Errorf("Test fail: run GET '%v' Expected status: %v received \n%v, \nexpected data: \n'%#v' received \n'%#v'",
			enPath, http.StatusOK, code, stRestful.UsersList, &resData)
		t.FailNow()
	}
}

func verifyLen(t *testing.T, url string, lenType string, length int) {
	code, _, _ := cr.HTTPDataMethod(cr.HTTPGetStr, url, "")

	curentLen := len(stRestful.UsersList.Users)
	if lenType == resourcesPath {
		curentLen = len(stRestful.UsersList.Resources)
	}else if lenType == groupsPath {
		curentLen = len(stRestful.UsersList.Groups)
	}
	if code != http.StatusOK || curentLen != length {
		t.Errorf("Test fail: run GET '%v' Expected status: %v recived %v, expected length: %v, received: %v",
			url, http.StatusOK, code, length, curentLen)
	}
}

func initState(t *testing.T) {
	// remove all users
	exeCommandCheckRes(t, cr.HTTPDeleteStr, enAllPath + usersPath, http.StatusNoContent, "", cr.StringMessage{Str: ""})
	// remove all resources
	exeCommandCheckRes(t, cr.HTTPDeleteStr, enAllPath + resourcesPath, http.StatusNoContent, "", cr.StringMessage{Str: ""})
	// remove all groups
	exeCommandCheckRes(t, cr.HTTPDeleteStr, enAllPath + groupsPath, http.StatusNoContent, "", cr.StringMessage{Str: ""})
	exeCommandCheckRes(t, cr.HTTPGetStr, enPath, http.StatusOK, "", *BasicUsers)
	verifyLen(t, enPath, usersPath, protectedEntityManagerLen)
	verifyLen(t, enPath, enAllPath + resourcesPath, protectedEntityManagerLen)
	verifyLen(t, enPath, groupsPath, 0)
}

// Initialize the UsersList to include all users from a given list
func setUm(t *testing.T, url string) {
	for i, name := range usersName {
		iURL := url + enServicePath
		okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", enServicePath + servicePath[usersIdx], name)}
		specificURL := iURL + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmUserCommand]), name)
		addDataVerifyResults(t, specificURL, okURLJ)
		verifyLen(t, enPath, usersPath, i+1+protectedEntityManagerLen)
	}
}

// Initialize the UsersList to include resource
func setResource(t *testing.T, url string) {
	for i, name := range resourcesName {
		iURL := url + enServicePath
		okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", enServicePath + servicePath[resourceIdx], name)}
		specificURL := iURL + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmResourceCommand]), name)
		addDataVerifyResults(t, specificURL, okURLJ)
		verifyLen(t, enPath, resourcesPath, i+1)
	}
}

// Initialize the UsersList to include groups
func setGroup(t *testing.T, url string) {
	iURL := url + enServicePath
	for i, gName := range groupsName {
		okURLJ := cr.URL{URL: fmt.Sprintf("%v/%v", enServicePath + servicePath[groupsIdx], gName)}
		specificURL := iURL + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmGroupCommand]), gName)
		addDataVerifyResults(t, specificURL, okURLJ)
		verifyLen(t, enPath, groupsPath, i+1)
	}
	setUm(t, url)
	gName := groupsName[0]
	for _, uName := range usersName {
		okURLJ := cr.URL{URL: fmt.Sprintf("%v%v/%v%v/%v", enServicePath + servicePath[groupsIdx], groupsPath, gName, servicePath[usersIdx], uName)}
		specificURL := iURL + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[addToGroupCommand]), gName, userIDToken, uName)
		addDataVerifyResults(t, specificURL, okURLJ)
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
		url := listener + enServicePath + servicePath[usersIdx] + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmCommand]), name)
		exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})
		verifyLen(t, enPath, usersPath, len(usersName)-i+1)
	}
}

// Test the following:
// 1. The group list is empty
// 2. Add a new group, verify the response code and that there is only one group with the same content
// 4. Add a new group, verify the response code and that there are 2 groups each with the extpected content
// 5. Remove the first group, verify the response code and that there is only one group, the second one
// 6. Remove the second group, verify the response code and that the group list is empty
func TestAddRemoveGroup(t *testing.T) {
	initState(t)
	setGroup(t, listener)
	// remove groups and verify that the number of groups decrease
	for i, name := range groupsName {
		url := listener + enServicePath + servicePath[groupsIdx] + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmCommand]), name)
//		d1, _ := json.Marshal(stRestful.UsersList)
//		t.Error("Ravid: d1 is", string(d1))
//		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, string(d1), stRestful.UsersList.(ent.EntityManager))
		exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})
		verifyLen(t, enPath, groupsPath, len(groupsName)-i-1)
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
		url := listener + enServicePath + servicePath[resourceIdx] + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleUmCommand]), name)
		exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})
		verifyLen(t, enPath, resourcesPath, len(resourcesName)-i-1)
	}
}
