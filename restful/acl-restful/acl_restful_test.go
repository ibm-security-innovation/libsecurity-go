package aclRestful

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/acl"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
)

const (
	host         = "http://localhost"
	port         = ":8082"
	listener     = host + port
	propertyName = defs.AclPropertyName

	userName1     = "User1"
	userName2     = "User2"
	groupName     = "group1"
	resourceName1 = "Disk1"
	resourceName2 = "Camera1"

	perRead  = "Read"
	perWrite = "Write"
	perExe   = "Execute"
	perTake  = "Take"
	perAll   = "Can be used by All"

	emptyRes      = "{}"
	permissionFmt = "%v-%v-%v"
)

var (
	resourcePath string

	stRestful *libsecurityRestful.LibsecurityRestful

	usersName        = []string{userName1, userName2}
	resourcesName    = []string{resourceName1, resourceName2}
	usersPermissions = []string{perRead, perWrite, perExe, perTake}
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	usersList := en.New()
	stRestful = libsecurityRestful.NewLibsecurityRestful()
	stRestful.SetData(usersList, nil, nil, nil, nil)
	stRestful.SetToFilterFlag(false)

	servicePath = cr.ServicePathPrefix + cr.Version + aclPrefix
	resourcePath = listener + servicePath

	go runServer()
	time.Sleep(100 * time.Millisecond)
}

func runServer() {
	wsContainer := restful.NewContainer()

	a := NewAclRestful()
	a.SetData(stRestful)
	a.RegisterBasic(wsContainer)

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
	case *acl.Acl:
		var a1 *acl.Acl
		json.Unmarshal([]byte(sData), &a1)
		data, _ := json.Marshal(a1)
		res = string(data)
		data, _ = json.Marshal(okJ.(*acl.Acl))
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
		t.Errorf("Test fail: status: %v, data %v, error: %v",
			expCode != code, exp != res, err)
		t.FailNow()
	}
	return res
}

func generateAcl() (string, *acl.Acl, error) {
	stRestful.UsersList.AddResource(resourceName1)
	stRestful.UsersList.AddGroup(groupName)
	for _, name := range usersName {
		stRestful.UsersList.AddUser(name)
		stRestful.UsersList.AddUserToGroup(groupName, name)
	}
	aclData := acl.NewACL()
	for _, name := range usersName {
		for _, p := range usersPermissions {
			stRestful.UsersList.AddPermission(en.Permission(p))
			aclData.AddPermissionToEntity(stRestful.UsersList, name, en.Permission(p))
		}
	}
	stRestful.UsersList.AddPermission(en.Permission(perAll))
	aclData.AddPermissionToEntity(stRestful.UsersList, defs.AclAllEntryName, perAll)
	stRestful.UsersList.AddPropertyToEntity(resourceName1, defs.AclPropertyName, aclData)
	data, _ := json.Marshal(aclData)
	return string(data), aclData, nil
}

func initState() {
	a := acl.NewACL()
	for _, name := range resourcesName {
		stRestful.UsersList.AddResource(name)
		stRestful.UsersList.AddPropertyToEntity(name, defs.AclPropertyName, a)
	}
	for _, name := range usersName {
		stRestful.UsersList.AddUser(name)
	}
}

// Add ACL property to resource and get it
// Remove the property and verify an error when try to get it
func Test_addGetRemoveAcl(t *testing.T) {
	initState()
	strFmt := "%v/%v/%v"
	for _, name := range resourcesName {
		okURLJ := cr.URL{URL: fmt.Sprintf(strFmt, servicePath, resourceToken, name)}
		url := fmt.Sprintf(strFmt, resourcePath, resourceToken, name)
		exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusCreated, emptyRes, okURLJ)
		data, _ := stRestful.UsersList.GetPropertyAttachedToEntity(name, propertyName)
		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", data.(*acl.Acl))
		exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})
		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusNotFound, "", cr.Error{Code: http.StatusNotFound})
	}
}

// Add a permission to resource for a given user and verify that it have it
// Remove the permission for the resource from the user and verify it doesn't have it
func Test_addCheckDeletePermission(t *testing.T) {
	initState()
	strFmt := "%v/%v"
	permission := en.Permission(perRead)

	stRestful.UsersList.AddPermission(en.Permission(permission))
	baseURL := fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handlePermissionCommand]),
		entityToken, userName1, resourceToken, resourceName1, permissionsToken, permission)
	okURLJ := cr.URL{URL: fmt.Sprintf(strFmt, servicePath, baseURL)}
	url := fmt.Sprintf(strFmt, resourcePath, baseURL)
	exeCommandCheckRes(t, cr.HTTPPutStr, url, http.StatusCreated, "", okURLJ)
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", cr.Match{Match: true, Message: ""})
	exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", cr.StringMessage{Str: ""})
	str := fmt.Sprintf("Permission '%v' doesn't allowed", permission)
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusNotFound, "", cr.Error{Code: 0, Message: str})
}

// Test estGetAllPermissionsOfEntity
// Add a set of permissions to resource for a given users list and verify that the respobse is as expected
func Test_getAllPermissionsOfEntity(t *testing.T) {
	initState()
	generateAcl()
	baseURL := fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[getAllPermissionsOfEntityCommand]), entityToken, userName1, resourceToken, resourceName1)
	url := fmt.Sprintf("%v/%v", resourcePath, baseURL)
	data, _ := acl.GetUserPermissions(stRestful.UsersList, userName1, resourceName1)
	res := []string{}
	for p := range data {
		res = append(res, string(p))
	}
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", res)
}

// Test restGetAllPermissions
// Add a set of permissions to resource for a given users list and verify that the respobse is as expected
func Test_getAllPermissions(t *testing.T) {
	initState()
	_, a, _ := generateAcl()
	baseURL := fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[getAllPermissionCommand]), permissionsToken, resourceToken, resourceName1)
	url := fmt.Sprintf("%v/%v", resourcePath, baseURL)
	data := a.GetAllPermissions()
	res := []string{}
	for p := range data {
		res = append(res, string(p))
	}
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", res)
}

// Test restGetWhoUsesAResourcePermission
// Add a set of permissions to resource for a given users list and verify that the respobse is as expected
func Test_getWhoUsesAResourcePermission(t *testing.T) {
	initState()
	generateAcl()
	permission := perAll
	baseURL := fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[getAllPermissionsOfEntityCommand]), resourceToken, resourceName1, permissionsToken, permission)
	url := fmt.Sprintf("%v/%v", resourcePath, baseURL)
	data := acl.GetWhoUseAPermission(stRestful.UsersList, resourceName1, permission)
	res := []string{}
	for p := range data {
		res = append(res, p)
	}
	exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", res)
}
