package accountsRestful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	am "github.com/ibm-security-innovation/libsecurity-go/accounts"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
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

func (l AmRestful) setAmRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleAuthenticateCommand], userPath)
	service.Route(service.PUT(str).
		To(l.restAm).
		Doc("Authenticate a user").
		Operation("authenticate").
		Reads(pUserData{}))

	str = fmt.Sprintf(urlCommands[handleAuthenticateCommand], logoutPath)
	service.Route(service.DELETE(str).To(l.restLogout).
		Doc("Logout the current user").
		Operation("logout"))
}

func (l AmRestful) setFullRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.PUT(str).
		Filter(l.st.SuperUserFilter).
		To(l.restAddAm).
		Doc("Add Account Management").
		Operation("AddNewAm").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(privilegePwd{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.GET(str).
		Filter(l.st.SameUserFilter).
		To(l.restGetAm).
		Doc("Get Account Management").
		Operation("getAm").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Writes(am.AmUserInfo{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.DELETE(str).
		Filter(l.st.SuperUserFilter).
		To(l.restDeleteAM).
		Doc("Remove Account Management").
		Operation("deleteAm").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleUserPwdCommand], usersPath, userIDParam, privilegePath)
	service.Route(service.PATCH(str).
		Filter(l.st.SuperUserFilter).
		To(l.restUpdatePrivilege).
		Doc("Update Account Management privilege").
		Operation("updatePrivilege").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(privilegeInfo{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUserPwdCommand], usersPath, userIDParam, pwdPath)
	service.Route(service.PATCH(str).
		Filter(l.st.SameUserUpdatePasswordFilter).
		To(l.restUpdatePwd).
		Doc("Update Account Management password").
		Operation("updatePwd").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(cr.UpdateSecret{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.PATCH(str).
		Filter(l.st.SuperUserFilter).
		To(l.restResetPwd).
		Doc("Reset user password").
		Operation("resetPwd").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Writes(cr.Secret{}))

	str = fmt.Sprintf(urlCommands[handleAuthenticateCommand], verifyPath)
	service.Route(service.GET(str).
		Filter(l.st.VerifyToken).
		To(l.restVerifyToken).
		Doc("Verify token").
		Operation("verifyToken"))
}

// RegisterFull : register the all the accounts interfaces to the RESTFul API container
func (l AmRestful) RegisterFull(container *restful.Container) {
	servicePath = cr.ServicePathPrefix + cr.Version + amPrefix

	service := new(restful.WebService)
	service.
		Path(servicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//		.Doc("Account Management and Authentication")

	l.setAmRoute(service)
	l.setFullRoute(service)
	container.Add(service)
}

// RegisterBasic : register the accounts login/logout to the RESTFul API container
func (l AmRestful) RegisterBasic(container *restful.Container) {
	servicePath = cr.ServicePathPrefix + cr.Version + amPrefix

	service := new(restful.WebService)
	service.
		Path(servicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//.Doc("Account Management and Authentication")

	l.setAmRoute(service)
	container.Add(service)
}
