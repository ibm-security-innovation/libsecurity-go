package otp_restful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/otp"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common_restful"
)

const (
	handleUserCommand = iota
	handleUserBlockCommand
	verifyUserCodeCommand
)

var (
	commandsToPath = []cr.ComamndsToPath{
		{handleUserCommand, "%v/{%v}"},
		{handleUserBlockCommand, "%v/{%v}/%v"},
		{verifyUserCodeCommand, "%v/{%v}/%v"},
	}

	urlCommands = make(cr.CommandToPath)
)

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

func (u otpRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.PUT(str).
		Filter(u.st.SuperUserFilter).
		To(u.restAddOtp).
		Doc("Add OTP").
		Operation("addOtp").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(cr.Secret{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.GET(str).
		Filter(u.st.SameUserFilter).
		To(u.restGetOtp).
		Doc("Get the OTP").
		Operation("getOtp").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Writes(otp.OtpUser{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], UsersPath, userIdParam)
	service.Route(service.DELETE(str).
		Filter(u.st.SuperUserFilter).
		To(u.restDeleteOtp).
		Doc("Remove the OTP").
		Operation("deleteOTP").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleUserBlockCommand], UsersPath, userIdParam, blockedStateToken)
	service.Route(service.GET(str).
		Filter(u.st.SameUserFilter).
		To(u.restIsOtpBlocked).
		Doc("Check if OTP is blocked").
		Operation("isOtpBlocked").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Writes(userState{}))

	str = fmt.Sprintf(urlCommands[handleUserBlockCommand], UsersPath, userIdParam, blockedStateToken)
	service.Route(service.PUT(str).
		Filter(u.st.SuperUserFilter).
		To(u.restSetOtpBlockedState).
		Doc("Set the OTP blocked state").
		Operation("setOtpBlockedState").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(userState{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[verifyUserCodeCommand], UsersPath, userIdParam, verifyHotpTypeParam)
	service.Route(service.POST(str).
		To(u.restVerifyOtpHotpUserCode). // no filter is needed
		Doc("Verify that a given OTP is as expected, counter base").
		Operation("verifyHotpUserCode").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(cr.Secret{}).
		Writes(cr.Match{}))

	str = fmt.Sprintf(urlCommands[verifyUserCodeCommand], UsersPath, userIdParam, verifyTotpTypeParam)
	service.Route(service.POST(str).
		To(u.restVerifyOtpTotpUserCode). // no filter is needed
		Doc("Verify that a given code is as expected, time base").
		Operation("verifyTotpUserCode").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(cr.Secret{}).
		Writes(cr.Match{}))
}

func (u otpRestful) RegisterBasic(container *restful.Container) {
	ServicePath = cr.ServicePathPrefix + cr.Version + OtpPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//.Doc("One Time Password")

	u.setRoute(service)
	container.Add(service)
}
