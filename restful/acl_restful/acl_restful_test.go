package acl_restful

/*
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emicklei/go-restful"
	"ibm-security-innovation/libsecurity-go/acl"
	en "ibm-security-innovation/libsecurity-go/entity"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	//	"ibm-security-innovation/libsecurity-go/restful/libsecurity"
	stc "ibm-security-innovation/libsecurity-go/defs"
	logger "ibm-security-innovation/libsecurity-go/logger"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	host     = "http://localhost"
	port     = ":8082"
	listener = host + port

	userName1        = "User1"
	userName2        = "User2"
	userInGroupName1 = "gUser1"
	userInGroupName2 = userName2
	groupName        = "support"
	resourceName     = "Disk1"

	savePermission    = "save"
	deletePermission  = "delete"
	canUsePermission  = "Can use"
	allPermission     = "All can use it"
	usersPermission   = "for users only"
	supportPermission = "Can take"

	PerRead  = "Read"
	PerWrite = "Write"
	PerExe   = "Execute"
	PerTake  = "Take"
	PerAll   = "Can be used by All"

	emptyRes      = "{}"
	permissionFmt = "%v-%v-%v"
)

var (
	resourcePath string

	stRestful *libsecurity_restful.LibsecurityRestful

	usersName        = []string{userName1, userName2, groupName}
	groupUsersName   = []string{userInGroupName1, userInGroupName2}
	usersPermissions = [][]string{{deletePermission, savePermission}, {canUsePermission, savePermission}, {canUsePermission, supportPermission}}
)

type permissionsVecS struct {
	val permissionsVecT
}

// Compare only the permissions: The order of the permissions is not relevant
func (p permissionsVecS) Equal(p1 permissionsVecS) bool {
	pVec := make(permissionsVecT)
	p1Vec := make(permissionsVecT)

	for permissions, _ := range p.val {
		pVec[permissions] = ""
	}
	for permissions, _ := range p1.val {
		p1Vec[permissions] = ""
	}
	return reflect.DeepEqual(pVec, p1Vec)
}

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	usersList := en.NewEntityManager()

	stRestful = libsecurity_restful.NewLibsecurityRestful()
	stRestful.SetData(usersList, nil, nil, nil, nil)
	stRestful.SetToFilterFlag(false)

	ServicePath = cr.ServicePathPrefix + cr.Version + AclPrefix
	resourcePath = listener + ServicePath

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
	case permissionsVecS:
		// The order of the dat is not relevant
		res = cr.RemoveSpaces(string(sData))
		d1, _ := json.Marshal(okJ.(permissionsVecS).val)
		var pu permissionsVecS
		err = json.Unmarshal([]byte(sData), &pu.val)
		if err == nil && pu.Equal(okJ.(permissionsVecS)) == false {
			exp = string(d1)
		} else {
			exp = res
		}
	case acl.PermissionSet:
		res = cr.RemoveSpaces(string(sData))
		d1, _ := json.Marshal(okJ.(acl.PermissionSet))
		var pu acl.PermissionSet
		json.Unmarshal([]byte(sData), &pu)
		if reflect.DeepEqual(pu, okJ.(acl.PermissionSet)) == false {
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

func generateAcl() (string, *acl.Acl, error) {
	stRestful.UsersList.AddResource(resourceName)
	stRestful.UsersList.AddGroup(groupName)
	for _, name := range usersName {
		stRestful.UsersList.AddUser(name)
		stRestful.UsersList.AddUserToGroup(groupName, name)
	}
	aclData := acl.NewACL()
	for i, _ := range usersPermissions {
		aclData.AddPermissionToResource(stRestful.UsersList, usersName[i], acl.Permission(usersPermission[i]))
	}
	data, _ := json.Marshal(aclData)
	return string(data), aclData, nil
}

func addAclVerifyResults(t *testing.T, url string, okJ cr.Url) {
	aclDataStr, aclData, err := generateAcl()
	if err != nil {
		t.Errorf("Test fail: Error: %v", err)
		t.Fail()
		return
	}
	exeCommandCheckRes(t, cr.PUT_STR, url, http.StatusCreated, aclDataStr, okJ)

	code, sData, _ := cr.HttpDataMethod(cr.GET_STR, url, "")
	var resData acl.Acl
	json.Unmarshal([]byte(sData), &resData)
	if code != http.StatusOK || aclData.IsEqual(resData) == false {
		t.Errorf("Test fail: run GET '%v' Expected status: %v received %v, expected data: '%v' received '%v'",
			url, http.StatusOK, code, aclData, resData)
		t.FailNow()
	}
}

func initState(t *testing.T) {
}

// Set the permission for the given princple: Users/Group or All
// and verify that the permission was setted as expected
func setPermissions(t *testing.T, url string, numOfPermissions int) {
	stRestful.UsersList.AddGroup(groupName)
	for _, name := range usersName {
		stRestful.UsersList.AddUser(name)
		stRestful.UsersList.AddUserToGroup(groupName, name)
	}
	for _, principleName := range usersName {
		permissions := make(permissionsVecT)
		for k := 0; k < numOfPermissions; k++ {
			permission := fmt.Sprintf(permissionFmt, principleName, PerRead, k)
			permissions[acl.Permission(permission)] = ""
			okUrlJ := cr.Url{Url: ServicePath + "/" + fmt.Sprintf(permissionUrlPath, principleName)}
			okUrlJ.Url = strings.TrimRight(okUrlJ.Url, "/")
			specificAcl := url + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handlePermissionCommand]),
				principleName, PermissionsToken, permission)
			exeCommandCheckRes(t, cr.PUT_STR, specificAcl, http.StatusCreated, "", okUrlJ)
		}
		// verify the permission list is as expected
		specificAcl := url + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[getPermissionCommand]), principleName)
		exeCommandCheckRes(t, cr.GET_STR, specificAcl, http.StatusOK, "", permissionsVecS{permissions})
	}
}

// Verify that the expected permissions are setted for the given princple: Users/Group or All
// Delete the permissions and verify that the permissions were cleared
func checkDeletePermissions(t *testing.T, url string, numOfPermissions int) {
	// check that the permission is setted and deleted and not permissions are left
	stRestful.UsersList.AddGroup(groupName)
	for _, principleName := range usersName {
		stRestful.UsersList.RemoveUserFromGroup(groupName, principleName)
		for k := 0; k < numOfPermissions; k++ {
			permission := fmt.Sprintf(permissionFmt, principleName, PerRead, k)
			match := cr.Match{Match: true}
			specificAcl := url + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handlePermissionCommand]),
				principleName, PermissionsToken, permission)
			exeCommandCheckRes(t, cr.GET_STR, specificAcl, http.StatusOK, "", match)
			exeCommandCheckRes(t, cr.DELETE_STR, specificAcl, http.StatusNoContent, "", cr.StringMessage{Str: ""})
		}
		// verify the permission list is as expected: empty
		specificAcl := url + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[getPermissionCommand]), principleName)
		exeCommandCheckRes(t, cr.GET_STR, specificAcl, http.StatusOK, "", cr.StringMessage{Str: emptyRes})
	}
}

// set permission for:
// 1. all + group
// 2. all
// 3. only for specific user
//   verify that the results are as expected
func TestPermissionWhoUses(t *testing.T) {
	permissions := []acl.Permission{PerAll, PerRead, PerWrite}

	initState(t)
	for i, permission := range permissions {
		// set all permission
		if i < 2 {
			specificAcl := resourcePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[getAllPermissionCommand]),
				stc.AclAllEntryName, PermissionsToken, permission)
			cr.HttpDataMethod(cr.PUT_STR, specificAcl, "")
		}
		// set groupName permission
		if i == 0 {
			specificAcl := resourcePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handlePermissionCommand]),
				groupName, PermissionsToken, permission)
			cr.HttpDataMethod(cr.PUT_STR, specificAcl, "")
		}
		// set user UserName1 permission
		if i == 2 {
			specificAcl := resourcePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handlePermissionCommand]),
				userName1, PermissionsToken, permission)
			cr.HttpDataMethod(cr.PUT_STR, specificAcl, "")
		}
		specificAcl := resourcePath + fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[getAllUsersOfPermissionCommand]),
			PermissionsToken, permission)
		stRestful.UsersList.GetPropertyAttachedToEntity(resourceName, stc.AclPropertyName)
		exeCommandCheckRes(t, cr.GET_STR, specificAcl, http.StatusOK, "", acl.GetWhoUseAPermission(stRestful.UsersList, resourceName, string(permission)))
	}
}
*/
