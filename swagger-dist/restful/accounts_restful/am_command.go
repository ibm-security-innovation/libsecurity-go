package accounts_restful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	am "ibm-security-innovation/libsecurity-go/accounts"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
)

const (
	handleAuthenticateCommand = iota
	handleUserCommand
	handleUserPwdCommand
)

var (
	commandsToPath = []cr.ComamndsToPath{
		{handleAuthenticateCommand, "%v"},
		{handleUserCommand, "%v/{%v}"},
		{handleUserPwdCommand, "%v/{%v}/%v"},
	}

	urlCommands = make(cr.CommandToPath)
)

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

func (l amRestful) setAmRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleAuthenticateCommand], UserPath)
	service.Route(service.PUT(str).
		To(l.restAm).
		Doc("Authenticate a user").
		Operation("authenticate").
		Reads(pUserData{}))

	str = fmt.Sprintf(urlCommands[handleAuthenticateCommand], LogoutPath)
	service.Route(service.DELETE(str).To(l.restLogout).
		Doc("Logout the current user").
		Operation("logout"))
}

func (l amRestful) setFullRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.PUT(str).
		Filter(l.st.SuperUserFilter).
		To(l.restAddAm).
		Doc("Add Account Management").
		Operation("AddNewAm").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(privilegePwd{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.GET(str).
		Filter(l.st.SameUserFilter).
		To(l.restGetAm).
		Doc("Get Account Management").
		Operation("getAm").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Writes(am.AmUserInfo{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.DELETE(str).
		Filter(l.st.SuperUserFilter).
		To(l.restDeleteAM).
		Doc("Remove Account Management").
		Operation("deleteAm").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleUserPwdCommand], UsersPath, userIdParam, PrivilegePath)
	service.Route(service.PATCH(str).
		Filter(l.st.SuperUserFilter).
		To(l.restUpdatePrivilege).
		Doc("Update Account Management privilege").
		Operation("updatePrivilege").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(privilegeInfo{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUserPwdCommand], UsersPath, userIdParam, PwdPath)
	service.Route(service.PATCH(str).
		Filter(l.st.SameUserFilter).
		To(l.restUpdatePwd).
		Doc("Update Account Management password").
		Operation("updatePwd").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(cr.UpdateSecret{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleAuthenticateCommand], VerifyPath)
	service.Route(service.GET(str).
		Filter(l.st.VerifyToken).
		To(l.restVerifyToken).
		Doc("Verify token").
		Operation("verifyToken"))
}

func (l amRestful) RegisterFull(container *restful.Container) {
	ServicePath = cr.ServicePathPrefix + cr.Version + AmPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//		.Doc("Account Management and Authentication")

	l.setAmRoute(service)
	l.setFullRoute(service)
	container.Add(service)
}

func (l amRestful) RegisterBasic(container *restful.Container) {
	ServicePath = cr.ServicePathPrefix + cr.Version + AmPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//.Doc("Account Management and Authentication")

	l.setAmRoute(service)
	container.Add(service)
}
