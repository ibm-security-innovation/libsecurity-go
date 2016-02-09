package aclRestful

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/acl"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
)

const (
	aclPrefix          = "/acl"
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
	servicePath string //= cr.ServicePathPrefix + "/acl"
)

// AclRestful : Acl restful structure
type AclRestful struct {
	st *libsecurityRestful.LibsecurityRestful
}

type resource struct {
	ResourceName string
	UserName     string
	Permission   string
}

func init() {
	initCommandToPath()
}

// NewAclRestful : return a pointer to the AclRestful structure
func NewAclRestful() *AclRestful {
	return &AclRestful{}
}

// SetData : initialize the AclRestful structure
func (a *AclRestful) SetData(stR *libsecurityRestful.LibsecurityRestful) {
	a.st = stR
}

func (a AclRestful) getURLPath(request *restful.Request, path string, name string) cr.URL {
	return cr.URL{URL: fmt.Sprintf("%v/%v/%v", servicePath, path, name)}
}

func (a *AclRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (a *AclRestful) getResourceAclData(request *restful.Request, response *restful.Response) (*acl.Acl, *resource, error) {
	var aclInfo resource
	var aclData *acl.Acl

	aclInfo.UserName = request.PathParameter(entityNameParam)
	aclInfo.ResourceName = request.PathParameter(resourceNameParam)
	aclInfo.Permission = request.PathParameter(permissionParam)
	data, err := cr.GetPropertyData(aclInfo.ResourceName, defs.AclPropertyName, a.st.UsersList)
	if err != nil {
		return nil, &aclInfo, err
	}
	aclData, ok := data.(*acl.Acl)
	if ok == false {
		return nil, &aclInfo, fmt.Errorf("ACL for resource '%v' is not valid", aclInfo.ResourceName)
	}
	return aclData, &aclInfo, nil
}

func (a *AclRestful) addAclToResource(request *restful.Request, response *restful.Response, resourceName string, newAcl *acl.Acl) bool {
	err := a.st.UsersList.AddPropertyToEntity(resourceName, defs.AclPropertyName, newAcl)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return false
	}
	return true
}

func (a *AclRestful) restAddAclToResource(request *restful.Request, response *restful.Response) {
	var a1 *acl.Acl
	resourceName := request.PathParameter(resourceNameParam)

	err := request.ReadEntity(&a1)
	if err != nil {
		a1 = acl.NewACL()
	}
	if a.addAclToResource(request, response, resourceName, a1) == false {
		return
	}
	response.WriteHeaderAndEntity(http.StatusCreated, a.getURLPath(request, resourceToken, resourceName))
}

func (a *AclRestful) restGetAclOfResource(request *restful.Request, response *restful.Response) {
	data, _, err := a.getResourceAclData(request, response)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeaderAndEntity(http.StatusOK, data)
}

func (a *AclRestful) restDeleteAclFromResource(request *restful.Request, response *restful.Response) {
	resourceName := request.PathParameter(resourceNameParam)
	err := a.st.UsersList.RemovePropertyFromEntity(resourceName, defs.AclPropertyName)
	if err != nil {
		a.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (a AclRestful) restCheckPermission(request *restful.Request, response *restful.Response) {
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
	response.WriteHeaderAndEntity(status, res)
}

func (a AclRestful) restSetPermission(request *restful.Request, response *restful.Response) {
	a1, aclInfo, err := a.getResourceAclData(request, response)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	if a1 == nil {
		eAcl := acl.NewACL()
		a.addAclToResource(request, response, aclInfo.ResourceName, eAcl)
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
		response.WriteHeaderAndEntity(http.StatusCreated, a.getURLPath(request, entityToken, fmt.Sprintf("%v/%v/%v/%v/%v", aclInfo.UserName, resourceToken, aclInfo.ResourceName, permissionsToken, aclInfo.Permission)))
	}
}

func (a AclRestful) restDeletePermission(request *restful.Request, response *restful.Response) {
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

func (a AclRestful) restGetAllPermissions(request *restful.Request, response *restful.Response) {
	aclData, _, err := a.getResourceAclData(request, response)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	res := aclData.GetAllPermissions()
	data := []string{}
	for name := range res {
		data = append(data, string(name))
	}
	response.WriteHeaderAndEntity(http.StatusOK, data)
}

func (a AclRestful) restGetAllPermissionsOfEntity(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter(entityNameParam)
	resourceName := request.PathParameter(resourceNameParam)
	res, err := acl.GetUserPermissions(a.st.UsersList, userName, resourceName)
	if err != nil {
		a.setError(response, http.StatusNotFound, err)
		return
	}
	data := []string{}
	for name := range res {
		data = append(data, string(name))
	}
	response.WriteHeaderAndEntity(http.StatusOK, data)
}

func (a AclRestful) restGetWhoUsesAResourcePermission(request *restful.Request, response *restful.Response) {
	resourceName := request.PathParameter(resourceNameParam)
	permission := request.PathParameter(permissionParam)
	res := acl.GetWhoUseAPermission(a.st.UsersList, resourceName, permission)
	data := []string{}
	for name := range res {
		data = append(data, name)
	}
	response.WriteHeaderAndEntity(http.StatusOK, data)
}
