package acl_restful

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	"ibm-security-innovation/libsecurity-go/acl"
	stc "ibm-security-innovation/libsecurity-go/defs"
	//	en "ibm-security-innovation/libsecurity-go/entity"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	AclPrefix = "/acl"

	entityComment      = "Entity name (All for 'world')"
	resourceComment    = "Resource (Entity) name"
	permissionComment  = "permission"
	descriptionComment = "permission description"
	entityToken        = "entity"
	resourceToken      = "resource"
	permissionsToken   = "permissions"
	descriptionToken   = "description"
	entityNameParam    = "entity-name"
	resourceNameParam  = "resource-name"
	permissionParam    = "permission"
	descriptionParam   = "description"
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

func (a *aclRestful) getResourceAclData(request *restful.Request, response *restful.Response) (*acl.Acl, *resource, error) {
	var aclInfo resource
	var aclData *acl.Acl

	aclInfo.UserName = request.PathParameter(entityNameParam)
	aclInfo.ResourceName = request.PathParameter(resourceNameParam)
	aclInfo.Permission = request.PathParameter(permissionParam)
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

func (a *aclRestful) addAclToResource(request *restful.Request, response *restful.Response, resourceName string) bool {
	a1 := acl.NewACL()
	err := a.st.UsersList.AddPropertyToEntity(resourceName, stc.AclPropertyName, a1)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return false
	}
	return true
}

func (a *aclRestful) restClearAclOfResource(request *restful.Request, response *restful.Response) {
	resourceName := request.PathParameter(resourceNameParam)
	if a.addAclToResource(request, response, resourceName) == false {
		return
	}
	response.WriteEntity(a.getUrlPath(request, resourceName))
	response.WriteHeader(http.StatusOK)
}

func (a *aclRestful) restGetAclOfResource(request *restful.Request, response *restful.Response) {
	data, _, err := a.getResourceAclData(request, response)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteEntity(data)
	response.WriteHeader(http.StatusOK)
}

func (a *aclRestful) restDeleteAclFromResource(request *restful.Request, response *restful.Response) {
	resourceName := request.PathParameter(resourceNameParam)
	err := a.st.UsersList.RemovePropertyFromEntity(resourceName, stc.AclPropertyName)
	if err != nil {
		a.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (a aclRestful) restCheckPermission(request *restful.Request, response *restful.Response) {
	a1, aclInfo, err := a.getResourceAclData(request, response)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	if a1 == nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	ok := false
	status := http.StatusOK
	if a1 != nil && aclInfo != nil {
		ok = acl.CheckUserPermission(a.st.UsersList, aclInfo.UserName, aclInfo.ResourceName, acl.Permission(aclInfo.Permission))
	}
	str := fmt.Sprintf("Permission '%v' is allowed", aclInfo.Permission)
	if ok == false {
		str = fmt.Sprintf("Permission '%v' doesn't allowed", aclInfo.Permission)
		status = http.StatusNotFound
	}
	res := cr.Match{Match: ok, Message: str}
	response.WriteHeader(status)
	response.WriteEntity(res)
}

func (a aclRestful) restSetPermission(request *restful.Request, response *restful.Response) {
	a1, aclInfo, err := a.getResourceAclData(request, response)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	if a1 == nil {
		a.addAclToResource(request, response, aclInfo.ResourceName)
		a1, aclInfo, err = a.getResourceAclData(request, response)
		if err != nil {
			a.setError(response, http.StatusInternalServerError, err)
			return
		}
	}
	err = a1.AddPermissionToResource(a.st.UsersList, aclInfo.UserName, acl.Permission(aclInfo.Permission))
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
	} else {
		response.WriteHeader(http.StatusCreated)
		response.WriteEntity(a.getUrlPath(request, aclInfo.Permission))
	}
}

func (a aclRestful) restDeletePermission(request *restful.Request, response *restful.Response) {
	aclData, aclInfo, err := a.getResourceAclData(request, response)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	err = aclData.RemovePermissionFromEntity(aclInfo.UserName, acl.Permission(aclInfo.Permission))
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (a aclRestful) restGetAllPermissions(request *restful.Request, response *restful.Response) {
	aclData, _, err := a.getResourceAclData(request, response)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	permissions := aclData.GetAllPermissions()
	ret := []acl.Permission{}
	for p, _ := range permissions {
		ret = append(ret, p)
	}
	response.WriteEntity(ret)
}

func (a aclRestful) restGetAllPermissionsOfEntity(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter(entityNameParam)
	resourceName := request.PathParameter(resourceNameParam)
	res, err := acl.GetUserPermissions(a.st.UsersList, userName, resourceName)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(res)
}

func (a aclRestful) restGetWhoUsesAResourcePermission(request *restful.Request, response *restful.Response) {
	resourceName := request.PathParameter(resourceNameParam)
	permission := request.PathParameter(permissionParam)
	res := acl.GetWhoUseAPermission(a.st.UsersList, resourceName, permission)
	data := []string{}
	response.WriteHeader(http.StatusOK)
	for name, _ := range res {
		data = append(data, name)
	}
	response.WriteEntity(data)
}
