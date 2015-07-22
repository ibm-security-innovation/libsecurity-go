package acl_restful

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	"ibm-security-innovation/libsecurity-go/acl"
	stc "ibm-security-innovation/libsecurity-go/defs"
	en "ibm-security-innovation/libsecurity-go/entity"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	AclPrefix = "/acl"

	entityComment      = "Entity name (All for 'world')"
	resourceComment    = "Resource (Entity) name"
	permissionComment  = "permission"
	descriptionComment = "permission description"
	PermissionsToken   = "permissions"
	DescriptionToken   = "description"
	//	entityNameParam    = "entity-name"
	//	resourceNameParam  = "resource-name"
	permissionParam  = "permission"
	descriptionParam = "description"
)

var (
	ServicePath string //= cr.ServicePathPrefix + "/acl"
)

type aclRestful struct {
	st *libsecurity_restful.LibsecurityRestful
}

type Config map[string]string

type permissionsVecT map[acl.Permission]interface{}

type resource struct {
	ResourceName string
	UserName     string
	Permission   string
}

func init() {
	initCommandToPath()
}

func NewAclRestful() *aclRestful {
	return &aclRestful{}
}

func (a *aclRestful) SetData(stR *libsecurity_restful.LibsecurityRestful) {
	a.st = stR
}

func (a aclRestful) getUrlPath(request *restful.Request, name string) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
}

func (a *aclRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (a aclRestful) checkEntityNameParamValidity(request *restful.Request, response *restful.Response, name string) bool {
	err := en.IsEntityNameValid(name)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return false
	}
	if a.st.UsersList.IsEntityInList(name) == false {
		err := fmt.Sprintf("Entity '%v' doesn't have ACL property", name)
		a.setError(response, http.StatusNotFound, errors.New(err))
		return false
	}
	return true
}

/*
func (a *aclRestful) restGetAclData(request *restful.Request, response *restful.Response) *acl.Acl {
	resorceName := request.PathParameter(resourceNameParam)
	if a.checkEntityNameParamValidity(request, response, aclName) == false {
		return nil
	}
	acl, _ := a.aclUsers.GetAclAddUserToGroup(aclName) // the acl is found from the previus check
	return acl
}
*/

func (a *aclRestful) getResourceAclData(request *restful.Request, response *restful.Response) (*acl.Acl, *resource, error) {
	var aclInfo resource
	var aclData *acl.Acl

	err := request.ReadEntity(&aclInfo)
	if err != nil {
		return nil, nil, err
	}
	data, err := cr.GetPropertyData(aclInfo.ResourceName, stc.AclPropertyName, a.st.UsersList)
	if err != nil {
		return nil, &aclInfo, err
	}
	aclData, ok := data.(*acl.Acl)
	if ok == false {
		return nil, &aclInfo, fmt.Errorf("ACL for resource '%v' is not valid", aclInfo.ResourceName)
	}
	return aclData, &aclInfo, nil
}

func (a *aclRestful) addAclToResource(request *restful.Request, response *restful.Response, name string) error {
	a1 := acl.NewACL()
	err := a.st.UsersList.AddPropertyToEntity(name, stc.AclPropertyName, a1)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return err
	}
	return nil
}

func (a *aclRestful) restGetAclOfResource(request *restful.Request, response *restful.Response) {
	data, _, err := a.getResourceAclData(request, response)
	if err != nil {
		return
	}
	response.WriteEntity(data)
	response.WriteHeader(http.StatusOK)
}

func (a *aclRestful) restDeleteAclFromResource(request *restful.Request, response *restful.Response) {
	var aclInfo resource

	err := request.ReadEntity(&aclInfo)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	err = a.st.UsersList.RemovePropertyFromEntity(aclInfo.ResourceName, stc.AclPropertyName)
	if err != nil {
		a.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (a aclRestful) getPermissions(request *restful.Request, response *restful.Response) {
	aclData, _, err := a.getResourceAclData(request, response)
	if err != nil {
		return
	}
	permissions := aclData.GetAllPermissions()
	ret := make(permissionsVecT)
	cnt := 0
	for p, _ := range permissions {
		ret[acl.Permission(fmt.Sprintf("%v", cnt))] = acl.Permission(p)
		cnt = cnt + 1
	}
	//	if err != nil {
	//		a.setError(response, http.StatusNotFound, err)
	//	} else {
	//		response.WriteEntity(ret)
	//	}
	response.WriteEntity(ret)
}

func (a aclRestful) restGetPermissions(request *restful.Request, response *restful.Response) {
	a.getPermissions(request, response)
}

func (a aclRestful) checkPermission(request *restful.Request, response *restful.Response) {
	a1, aclInfo, err := a.getResourceAclData(request, response)
	if a1 == nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	ok := false
	status := http.StatusOK
	if a1 != nil && aclInfo != nil {
		ok = acl.CheckUserPermission(a.st.UsersList, aclInfo.UserName, aclInfo.ResourceName, acl.Permission(aclInfo.Permission))
	}
	str := fmt.Sprintf("Permission '%s' is allowed", aclInfo.Permission)
	if ok == false {
		str = fmt.Sprintf("Permission '%s' doesn't allowed", aclInfo.Permission)
		status = http.StatusNotFound
	}
	res := cr.Match{Match: ok, Message: str}
	response.WriteHeader(status)
	response.WriteEntity(res)
}

func (a aclRestful) restCheckPermission(request *restful.Request, response *restful.Response) {
	a.checkPermission(request, response)
}

func (a aclRestful) setPermission(request *restful.Request, response *restful.Response) {
	a1, aclInfo, err := a.getResourceAclData(request, response)
	if a1 == nil {
		a.addAclToResource(request, response, aclInfo.ResourceName)
		a1, aclInfo, _ = a.getResourceAclData(request, response)
	}
	err = a1.AddPermissionToResource(a.st.UsersList, aclInfo.UserName, acl.Permission(aclInfo.Permission))
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
	} else {
		response.WriteHeader(http.StatusCreated)
		response.WriteEntity(a.getUrlPath(request, aclInfo.Permission))
	}
}

func (a aclRestful) restSetPermission(request *restful.Request, response *restful.Response) {
	a.setPermission(request, response)
}

func (a aclRestful) deletePermission(request *restful.Request, response *restful.Response) {
	aclData, aclInfo, err := a.getResourceAclData(request, response)
	if err != nil {
		return
	}
	err = aclData.RemovePermissionFromEntity(aclInfo.UserName, acl.Permission(aclInfo.Permission))
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (a aclRestful) restDeletePermission(request *restful.Request, response *restful.Response) {
	a.deletePermission(request, response)
}

/*

func (a aclRestful) restGetAllUsersOfPermission(request *restful.Request, response *restful.Response) {
	aclData := a.restGetAclData(request, response)
	if aclData == nil {
		return
	}
	permission := acl.Permission(request.PathParameter(permissionParam))
	response.WriteEntity(aclData.GetWhoUseAPermission(permission.Name))
}
*/
