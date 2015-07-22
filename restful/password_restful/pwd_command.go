package password_restful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	"ibm-security-innovation/libsecurity-go/password"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
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

func (p pwdRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.PUT(str).
		Filter(p.st.SuperUserFilter).
		To(p.restAddPwd).
		Doc("Add Password").
		Operation("AddPwd").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(secretData{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.GET(str).Filter(p.st.SameUserFilter).
		To(p.restGetPwd).
		Doc("Get Password").
		Operation("getPwd").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Writes(password.UserPwd{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.DELETE(str).
		Filter(p.st.SuperUserFilter).
		To(p.restDeletePwd).
		Doc("Remove Password").
		Operation("deletePwd").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.PATCH(str).
		Filter(p.st.SameUserFilter).
		To(p.restUpdatePassword).
		Doc("Update Password").
		Operation("updatePassword").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(cr.UpdateSecret{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[verifyUserPasswordCommand], UsersPath, userIdParam)
	service.Route(service.POST(str).
		Filter(p.st.SameUserFilter).
		To(p.restVerifyPassword).
		Doc("Verify that a given password is as expected").
		Operation("verifyPassword").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(secretData{}).
		Writes(cr.Match{}))

	str = fmt.Sprintf(urlCommands[resetUserPasswordCommand], UsersPath, userIdParam, ResetUserPwdPath)
	service.Route(service.GET(str).
		Filter(p.st.SuperUserFilter).
		To(p.restResetPassword).
		Doc("Reset password").
		Operation("resetPassword").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Writes(secretData{}))
}

func (p pwdRestful) RegisterBasic(container *restful.Container) {
	ServicePath = cr.ServicePathPrefix + cr.Version + PwdPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//.Doc("Password Management")

	p.setRoute(service)
	container.Add(service)
}
