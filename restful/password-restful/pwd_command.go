package passwordRestful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/password"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
)

const (
	handleUserCommand = iota
	verifyUserPasswordCommand
	resetUserPasswordCommand
)

var (
	commandsToPath = []cr.ComamndsToPath{
		{handleUserCommand, "%v/{%v}"},
		{verifyUserPasswordCommand, "%v/{%v}"},
		{resetUserPasswordCommand, "%v/{%v}/%v"},
	}
	urlCommands = make(cr.CommandToPath)
)

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

func (p PwdRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.PUT(str).
		Filter(p.st.SuperUserFilter).
		To(p.restAddPwd).
		Doc("Add Password").
		Operation("AddPwd").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(secretData{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.GET(str).Filter(p.st.SameUserFilter).
		To(p.restGetPwd).
		Doc("Get Password").
		Operation("getPwd").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Writes(password.UserPwd{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.DELETE(str).
		Filter(p.st.SuperUserFilter).
		To(p.restDeletePwd).
		Doc("Remove Password").
		Operation("deletePwd").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.PATCH(str).
		Filter(p.st.SameUserFilter).
		To(p.restUpdatePassword).
		Doc("Update Password").
		Operation("updatePassword").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(cr.UpdateSecret{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[verifyUserPasswordCommand], usersPath, userIDParam)
	service.Route(service.POST(str).
		Filter(p.st.SameUserFilter).
		To(p.restVerifyPassword).
		Doc("Verify that a given password is as expected").
		Operation("verifyPassword").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(secretData{}).
		Writes(cr.Match{}))

	str = fmt.Sprintf(urlCommands[resetUserPasswordCommand], usersPath, userIDParam, resetUserPwdPath)
	service.Route(service.POST(str).
		Filter(p.st.SuperUserFilter).
		To(p.restResetPassword).
		Doc("Reset password").
		Operation("resetPassword").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Writes(secretData{}))
}

// RegisterBasic : register the Password to the RESTFul API container
func (p PwdRestful) RegisterBasic(container *restful.Container) {
	servicePath = cr.ServicePathPrefix + cr.Version + pwdPrefix

	service := new(restful.WebService)
	service.
		Path(servicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//.Doc("Password Management")

	p.setRoute(service)
	container.Add(service)
}
