package entityRestful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	ent "github.com/ibm-security-innovation/libsecurity-go/entity"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
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
		{handleUmGroupCommand, groupsPath + "/{%v}"},
		{handleUmUserCommand, usersPath + "/{%v}"},
		{handleUmResourceCommand, resourcesPath + "/{%v}"},
		{handleAllUmGroupCommand, groupsPath},
		{handleAllUmUserCommand, usersPath},
		{handleAllUmResourceCommand, resourcesPath},
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

func (en EnRestful) setGroupRoute(ws *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUmGroupCommand], groupIDParam)
	ws.Route(ws.PUT(str).
		Filter(en.st.SuperUserFilter).
		To(en.restCreateGroup).
		Doc("Create a group").
		Operation("createGroup").
		Param(ws.PathParameter(groupIDParam, groupIDComment).DataType("string")).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUmGroupCommand], groupIDParam)
	ws.Route(ws.GET(str).
		Filter(en.st.SuperUserFilter).
		To(en.restGetGroup).
		Doc("Get a group").
		Operation("getGroup").
		Param(ws.PathParameter(groupIDParam, groupIDComment).DataType("string")).
		Writes(ent.Group{}))

	str = fmt.Sprintf(urlCommands[handleUmGroupCommand], groupIDParam)
	ws.Route(ws.DELETE(str).
		Filter(en.st.SuperUserFilter).
		To(en.restRemoveGroup).
		Doc("Delete a group").
		Operation("removeGroup").
		Param(ws.PathParameter(groupIDParam, groupIDComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleAllUmGroupCommand])
	ws.Route(ws.DELETE(str).
		Filter(en.st.SuperUserFilter).
		To(en.restRemoveAllGroups).
		Doc("Delete all groups").
		Operation("deleteAllGroups"))

	str = fmt.Sprintf(urlCommands[addToGroupCommand], groupIDParam, userIDToken, userIDParam)
	ws.Route(ws.PUT(str).
		Filter(en.st.SuperUserFilter).
		To(en.restAddUserToGroup).
		Doc("Add a user to a group").
		Operation("addUserToGroup").
		Param(ws.PathParameter(groupIDParam, groupIDComment).DataType("string")).
		Param(ws.PathParameter(userIDParam, userIDComment).DataType("string")).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[addToGroupCommand], groupIDParam, userIDToken, userIDParam)
	ws.Route(ws.DELETE(str).
		Filter(en.st.SuperUserFilter).
		To(en.restRemoveUserFromGroup).
		Doc("Remove a user from a group").
		Operation("removeUserToGroup").
		Param(ws.PathParameter(groupIDParam, groupIDComment).DataType("string")).
		Param(ws.PathParameter(userIDParam, userIDComment).DataType("string")).
		Writes(cr.URL{}))
}

func (en EnRestful) setUserRoute(ws *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleAllUmCommand])
	ws.Route(ws.GET(str).
		Filter(en.st.SuperUserFilter).
		To(en.restGetEntityManager).
		Doc("Get Entity management").
		Operation("getEntityManager").
		Writes(ent.EntityManager{}))

	str = fmt.Sprintf(urlCommands[handleUmUserCommand], userIDParam)
	ws.Route(ws.PUT(str).
		Filter(en.st.SuperUserFilter).
		To(en.restCreateUser).
		Doc("Create user").
		Operation("createUser").
		Param(ws.PathParameter(userIDParam, userIDComment).DataType("string")).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUmUserCommand], userIDParam)
	ws.Route(ws.GET(str).
		Filter(en.st.SameUserFilter).
		To(en.restGetUser).
		Doc("Get user").
		Operation("getUser").
		Param(ws.PathParameter(userIDParam, userIDComment).DataType("string")).
		Writes(ent.Entity{}))

	str = fmt.Sprintf(urlCommands[handleUmUserCommand], userIDParam)
	ws.Route(ws.DELETE(str).
		Filter(en.st.SuperUserFilter).
		To(en.restRemoveUser).
		Doc("Delete user").
		Operation("removeUser").
		Param(ws.PathParameter(userIDParam, userIDComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleAllUmUserCommand])
	ws.Route(ws.DELETE(str).
		Filter(en.st.SuperUserFilter).
		To(en.restRemoveAllUsers).
		Doc("Delete all users").
		Operation("removeAllUsers"))
}

func (en EnRestful) setResourceRoute(ws *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUmResourceCommand], resourceIDParam)
	ws.Route(ws.PUT(str).
		Filter(en.st.SuperUserFilter).
		To(en.restCreateResource).
		Doc("Create resource").
		Operation("createResource").
		Param(ws.PathParameter(resourceIDParam, resourceIDComment).DataType("string")).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUmResourceCommand], resourceIDParam)
	ws.Route(ws.GET(str).
		Filter(en.st.SameUserFilter).
		To(en.restGetResource).
		Doc("Get resource").
		Operation("getResource").
		Param(ws.PathParameter(resourceIDParam, resourceIDComment).DataType("string")).
		Writes(ent.Entity{}))

	str = fmt.Sprintf(urlCommands[handleUmResourceCommand], resourceIDParam)
	ws.Route(ws.DELETE(str).
		Filter(en.st.SuperUserFilter).
		To(en.restRemoveResource).
		Doc("Delete resource").
		Operation("removeResource").
		Param(ws.PathParameter(resourceIDParam, resourceIDComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleAllUmResourceCommand])
	ws.Route(ws.DELETE(str).
		Filter(en.st.SuperUserFilter).
		To(en.restRemoveAllResources).
		Doc("Delete all resources").
		Operation("removeAllResources"))

}

// RegisterBasic : register the entity to the RESTFul API container
func (en EnRestful) RegisterBasic(container *restful.Container) {
	enServicePath = cr.ServicePathPrefix + cr.Version + umPrefix

	service := new(restful.WebService)
	service.
		Path(enServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	// .Doc("Users and Groups Management")

	en.setUserRoute(service)
	en.setGroupRoute(service)
	en.setResourceRoute(service)
	container.Add(service)
}
