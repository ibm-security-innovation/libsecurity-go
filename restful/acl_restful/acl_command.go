package acl_restful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/acl"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common_restful"
)

const (
	handleAclCommand = iota
	handlePermissionCommand
	getAllPermissionCommand
	getAllPermissionsOfEntityCommand

	permissionUrlPath = "%v"
)

var (
	commandsToPath = []cr.ComamndsToPath{
		{handleAclCommand, "%v/{%v}"},
		{handlePermissionCommand, "%v/{%v}/%v/{%v}/%v/{%v}"},
		{getAllPermissionCommand, "%v/%v/{%v}"},
		{getAllPermissionsOfEntityCommand, "%v/{%v}/%v/{%v}"},
	}
	urlCommands = make(cr.CommandToPath)
)

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

func (a aclRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleAclCommand], resourceToken, resourceNameParam)
	service.Route(service.PUT(str).
		Filter(a.st.SuperUserFilter).
		To(a.restAddAclToResource).
		Doc("Add ACL to resource").
		Operation("addAclToResource").
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")).
		Reads(acl.Acl{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleAclCommand], resourceToken, resourceNameParam)
	service.Route(service.GET(str).
		Filter(a.st.SameUserFilter).
		To(a.restGetAclOfResource).
		Doc("Get ACL attached to resource").
		Operation("getAcl").
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")).
		Writes(acl.Acl{}))

	str = fmt.Sprintf(urlCommands[handleAclCommand], resourceToken, resourceNameParam)
	service.Route(service.DELETE(str).
		Filter(a.st.SuperUserFilter).
		To(a.restDeleteAclFromResource).
		Doc("Remove ACL from resource").
		Operation("deleteAcl").
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")))
}

func (a aclRestful) setUsersRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handlePermissionCommand], entityToken, entityNameParam, resourceToken, resourceNameParam, permissionsToken, permissionParam)
	service.Route(service.PUT(str).
		Filter(a.st.SuperUserFilter).
		To(a.restSetPermission).
		Doc("Grant the premission to the given entity for a given resource").
		Operation("setPermission").
		Param(service.PathParameter(entityNameParam, entityComment).DataType("string")).
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")).
		Param(service.PathParameter(permissionParam, permissionComment).DataType("string")).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handlePermissionCommand], entityToken, entityNameParam, resourceToken, resourceNameParam, permissionsToken, permissionParam)
	service.Route(service.GET(str).
		Filter(a.st.SameUserFilter).
		To(a.restCheckPermission).
		Doc("Check if the entity has the given permission to the resource").
		Operation("checkEntityPermissionToResource").
		Param(service.PathParameter(entityNameParam, entityComment).DataType("string")).
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")).
		Param(service.PathParameter(permissionParam, permissionComment).DataType("string")).
		Writes(cr.Match{}))

	str = fmt.Sprintf(urlCommands[handlePermissionCommand], entityToken, entityNameParam, resourceToken, resourceNameParam, permissionsToken, permissionParam)
	service.Route(service.DELETE(str).
		Filter(a.st.SuperUserFilter).
		To(a.restDeletePermission).
		Doc("Revoke the permission of the given entity for the given resource").
		Operation("deleteEntityPermissionFromAResource").
		Param(service.PathParameter(entityNameParam, entityComment).DataType("string")).
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")).
		Param(service.PathParameter(permissionParam, permissionComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[getAllPermissionCommand], permissionsToken, resourceToken, resourceNameParam)
	service.Route(service.GET(str).
		Filter(a.st.SameUserFilter).
		To(a.restGetAllPermissions).
		Doc("Get all the permissions of the given resource").
		Operation("getUserGroupPermissions").
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[getAllPermissionsOfEntityCommand], entityToken, entityNameParam, resourceToken, resourceNameParam)
	service.Route(service.GET(str).
		Filter(a.st.SameUserFilter).
		To(a.restGetAllPermissionsOfEntity).
		Doc("Get all the permissions of the entity").
		Operation("getAllEntityPermission").
		Param(service.PathParameter(entityNameParam, entityComment).DataType("string")).
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[getAllPermissionsOfEntityCommand], resourceToken, resourceNameParam, permissionsToken, permissionParam)
	service.Route(service.GET(str).
		Filter(a.st.SuperUserFilter).
		To(a.restGetWhoUsesAResourcePermission).
		Doc("Get all the entities that have the permission to the resource").
		Operation("getAllEntitiesOfPermission").
		Param(service.PathParameter(resourceNameParam, resourceComment).DataType("string")).
		Param(service.PathParameter(permissionParam, permissionComment).DataType("string")))
}

func (a aclRestful) RegisterBasic(container *restful.Container) {
	ServicePath = cr.ServicePathPrefix + cr.Version + AclPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//	.Doc("Access Control List")
	a.setRoute(service)
	a.setUsersRoute(service)
	container.Add(service)
}
