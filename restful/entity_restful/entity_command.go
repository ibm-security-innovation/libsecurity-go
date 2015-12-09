package entity_restful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common_restful"
)

const (
	handleUmCommand = iota
	handleUmGroupCommand
	handleUmUserCommand
	handleUmResourceCommand
	handleAllUmGroupCommand
	handleAllUmUserCommand
	handleAllUmResourceCommand
	handleAllUmCommand
	addToGroupCommand
)

var (
	commandsToPath = []cr.ComamndsToPath{
		{handleUmCommand, "/{%v}"},
		{handleUmGroupCommand, GroupsPath + "/{%v}"},
		{handleUmUserCommand, UsersPath + "/{%v}"},
		{handleUmResourceCommand, ResourcesPath + "/{%v}"},
		{handleAllUmGroupCommand, GroupsPath},
		{handleAllUmUserCommand, UsersPath},
		{handleAllUmResourceCommand, ResourcesPath},
		{handleAllUmCommand, ""},
		{addToGroupCommand, "/{%v}/%v/{%v}"},
	}
	urlCommands = make(cr.CommandToPath)
)

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

func (g enRestful) setGroupRoute(ws *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUmGroupCommand], groupIdParam)
	ws.Route(ws.PUT(str).
		Filter(g.st.SuperUserFilter).
		To(g.restCreateGroup).
		Doc("Create a group").
		Operation("createGroup").
		Param(ws.PathParameter(groupIdParam, groupIdComment).DataType("string")).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUmGroupCommand], groupIdParam)
	ws.Route(ws.GET(str).
		Filter(g.st.SuperUserFilter).
		To(g.restGetGroup).
		Doc("Get a group").
		Operation("getGroup").
		Param(ws.PathParameter(groupIdParam, groupIdComment).DataType("string")).
		Writes(en.Group{}))

	str = fmt.Sprintf(urlCommands[handleUmGroupCommand], groupIdParam)
	ws.Route(ws.DELETE(str).
		Filter(g.st.SuperUserFilter).
		To(g.restRemoveGroup).
		Doc("Delete a group").
		Operation("removeGroup").
		Param(ws.PathParameter(groupIdParam, groupIdComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleAllUmGroupCommand])
	ws.Route(ws.DELETE(str).
		Filter(g.st.SuperUserFilter).
		To(g.restRemoveAllGroups).
		Doc("Delete all groups").
		Operation("deleteAllGroups"))

	str = fmt.Sprintf(urlCommands[addToGroupCommand], groupIdParam, userIdToken, userIdParam)
	ws.Route(ws.PUT(str).
		Filter(g.st.SuperUserFilter).
		To(g.restAddUserToGroup).
		Doc("Add a user to a group").
		Operation("addUserToGroup").
		Param(ws.PathParameter(groupIdParam, groupIdComment).DataType("string")).
		Param(ws.PathParameter(userIdParam, userIdComment).DataType("string")).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[addToGroupCommand], groupIdParam, userIdToken, userIdParam)
	ws.Route(ws.DELETE(str).
		Filter(g.st.SuperUserFilter).
		To(g.restRemoveUserFromGroup).
		Doc("Remove a user from a group").
		Operation("removeUserToGroup").
		Param(ws.PathParameter(groupIdParam, groupIdComment).DataType("string")).
		Param(ws.PathParameter(userIdParam, userIdComment).DataType("string")).
		Writes(cr.Url{}))
}

func (u enRestful) setUserRoute(ws *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleAllUmCommand])
	ws.Route(ws.GET(str).
		Filter(u.st.SuperUserFilter).
		To(u.restGetEntityManager).
		Doc("Get Entity management").
		Operation("getEntityManager").
		Writes(en.EntityManager{}))

	str = fmt.Sprintf(urlCommands[handleUmUserCommand], userIdParam)
	ws.Route(ws.PUT(str).
		Filter(u.st.SuperUserFilter).
		To(u.restCreateUser).
		Doc("Create user").
		Operation("createUser").
		Param(ws.PathParameter(userIdParam, userIdComment).DataType("string")).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUmUserCommand], userIdParam)
	ws.Route(ws.GET(str).
		Filter(u.st.SameUserFilter).
		To(u.restGetUser).
		Doc("Get user").
		Operation("getUser").
		Param(ws.PathParameter(userIdParam, userIdComment).DataType("string")).
		Writes(en.Entity{}))

	str = fmt.Sprintf(urlCommands[handleUmUserCommand], userIdParam)
	ws.Route(ws.DELETE(str).
		Filter(u.st.SuperUserFilter).
		To(u.restRemoveUser).
		Doc("Delete user").
		Operation("removeUser").
		Param(ws.PathParameter(userIdParam, userIdComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleAllUmUserCommand])
	ws.Route(ws.DELETE(str).
		Filter(u.st.SuperUserFilter).
		To(u.restRemoveAllUsers).
		Doc("Delete all users").
		Operation("removeAllUsers"))
}

func (u enRestful) setResourceRoute(ws *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUmResourceCommand], resourceIdParam)
	ws.Route(ws.PUT(str).
		Filter(u.st.SuperUserFilter).
		To(u.restCreateResource).
		Doc("Create resource").
		Operation("createResource").
		Param(ws.PathParameter(resourceIdParam, resourceIdComment).DataType("string")).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUmResourceCommand], resourceIdParam)
	ws.Route(ws.GET(str).
		Filter(u.st.SameUserFilter).
		To(u.restGetResource).
		Doc("Get resource").
		Operation("getResource").
		Param(ws.PathParameter(resourceIdParam, resourceIdComment).DataType("string")).
		Writes(en.Entity{}))

	str = fmt.Sprintf(urlCommands[handleUmResourceCommand], resourceIdParam)
	ws.Route(ws.DELETE(str).
		Filter(u.st.SuperUserFilter).
		To(u.restRemoveResource).
		Doc("Delete resource").
		Operation("removeResource").
		Param(ws.PathParameter(resourceIdParam, resourceIdComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleAllUmResourceCommand])
	ws.Route(ws.DELETE(str).
		Filter(u.st.SuperUserFilter).
		To(u.restRemoveAllResources).
		Doc("Delete all resources").
		Operation("removeAllResources"))

}

//func (u enRestful) RegisterBasic(container *restful.Container) {
//	service := new(restful.WebService)
//	service.
//		Path(UsersServicePath).
//		Consumes(restful.MIME_JSON).
//		Produces(restful.MIME_JSON)
//
//	u.setUserRoute(service)
//	container.Add(service)
//}

func (u enRestful) RegisterBasic(container *restful.Container) {
	EnServicePath = cr.ServicePathPrefix + cr.Version + UmPrefix

	service := new(restful.WebService)
	service.
		Path(EnServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	// .Doc("Users and Groups Management")

	u.setUserRoute(service)
	u.setGroupRoute(service)
	u.setResourceRoute(service)
	container.Add(service)
}
