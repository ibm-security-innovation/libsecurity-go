package acl_restful

import (
	"fmt"

	//	"ibm-security-innovation/libsecurity-go/acl"
	"github.com/emicklei/go-restful"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
)

const (
	handlePermissionCommand = iota
	getPermissionCommand
	getAllPermissionCommand
	getAllUsersOfPermissionCommand

	permissionUrlPath = "%v"
)

var (
	commandsToPath = []cr.ComamndsToPath{
		{handlePermissionCommand, "%v"},
		//		{getPermissionCommand, "%v/{%v}/{%v}"},
		//		{getAllPermissionCommand, "%v/{%v}/%v"},
		//		{getAllUsersOfPermissionCommand, "%v/{%v}/%v/{%v}"},
	}
	urlCommands = make(cr.CommandToPath)
)

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

// acl.AddPermissionToEntity(el *en.EntityManager, entityName string, permission Permission) error
// acl.RemovePermissionFromEntity(entityName string, permission Permission) error
// GetAllPermissions() PermissionsT // get all the permissions of the object
// GetUserPermissions(el *en.EntityManager, userName string, entityName string) (PermissionsT, error) {
// CheckUserPermission(el *en.EntityManager, userName string, entityName string, permission Permission) bool {
// GetWhoUseAPermission(el *en.EntityManager, entityName string, permission string) PermissionSet {

func (a aclRestful) setUsersRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handlePermissionCommand], permissionParam)
	service.Route(service.PUT(str).
		Filter(a.st.SuperUserFilter).
		To(a.restSetPermission).
		Doc("Grant the premission to the given entity for a given resource").
		Operation("setPermission").
		Reads(resource{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handlePermissionCommand], permissionParam)
	service.Route(service.GET(str).
		Filter(a.st.SameUserFilter).
		To(a.restCheckPermission).
		Doc("Check if the entity has the given permission to the resource").
		Operation("checkEntityPermissionToResource").
		Reads(resource{}).
		Writes(cr.Match{}))

	str = fmt.Sprintf(urlCommands[handlePermissionCommand], permissionParam)
	service.Route(service.DELETE(str).
		Filter(a.st.SuperUserFilter).
		To(a.restDeletePermission).
		Doc("Revoke the permission of the given entity for the given resource").
		Operation("deleteEntityPermissionFromAResource").
		Reads(resource{}))

	/*
		str = fmt.Sprintf(urlCommands[getPermissionCommand], resourecNameParam, entityNameParam)
		service.Route(service.GET(str).
			Filter(a.st.SameUserFilter).
			To(a.restGetPermissions).
			Doc("Get all the permissions of the given entity").
			Operation("getUserGroupPermissions").
			Param(service.PathParameter(resourceNameParam, entityComment).DataType("string")).
			Param(service.PathParameter(entityNameParam, entityComment).DataType("string")).
	*/
}

/*
func (a aclRestful) setPermissionsRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[getAllUsersOfPermissionCommand], AclsPath, aclNameParam, PermissionsToken, permissionParam)
	service.Route(service.GET(str).
		Filter(a.st.SuperUserFilter).
		To(a.restGetAllUsersOfPermission).
		Doc("Get all the users/groups and ALL that uses the permission").
		Operation("getAllUsersOfPermission").
		Param(service.PathParameter(aclNameParam, aclComment).DataType("string")).
		Param(service.PathParameter(permissionParam, permissionComment).DataType("string")).
		Writes(acl.PermissionSet{}))
}
*/

func (a aclRestful) RegisterBasic(container *restful.Container) {
	ServicePath = cr.ServicePathPrefix + cr.Version + AclPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//	.Doc("Access Control List")
	a.setUsersRoute(service)
	//	a.setPermissionsRoute(service)
	container.Add(service)
}
