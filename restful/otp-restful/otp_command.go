package otpRestful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/otp"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
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

func (u OtpRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.PUT(str).
		Filter(u.st.SuperUserFilter).
		To(u.restAddOtp).
		Doc("Add OTP").
		Operation("addOtp").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(cr.Secret{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.GET(str).
		Filter(u.st.SameUserFilter).
		To(u.restGetOtp).
		Doc("Get the OTP").
		Operation("getOtp").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Writes(otp.UserInfoOtp{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.DELETE(str).
		Filter(u.st.SuperUserFilter).
		To(u.restDeleteOtp).
		Doc("Remove the OTP").
		Operation("deleteOTP").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleUserBlockCommand], usersPath, userIDParam, blockedStateToken)
	service.Route(service.GET(str).
		Filter(u.st.SameUserFilter).
		To(u.restIsOtpBlocked).
		Doc("Check if OTP is blocked").
		Operation("isOtpBlocked").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Writes(userState{}))

	str = fmt.Sprintf(urlCommands[handleUserBlockCommand], usersPath, userIDParam, blockedStateToken)
	service.Route(service.PUT(str).
		Filter(u.st.SuperUserFilter).
		To(u.restSetOtpBlockedState).
		Doc("Set the OTP blocked state").
		Operation("setOtpBlockedState").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(userState{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[verifyUserCodeCommand], usersPath, userIDParam, verifyHotpTypeParam)
	service.Route(service.POST(str).
		To(u.restVerifyOtpHotpUserCode). // no filter is needed
		Doc("Verify that a given OTP is as expected, counter base").
		Operation("verifyHotpUserCode").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(cr.Secret{}).
		Writes(cr.Match{}))

	str = fmt.Sprintf(urlCommands[verifyUserCodeCommand], usersPath, userIDParam, verifyTotpTypeParam)
	service.Route(service.POST(str).
		To(u.restVerifyOtpTotpUserCode). // no filter is needed
		Doc("Verify that a given code is as expected, time base").
		Operation("verifyTotpUserCode").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(cr.Secret{}).
		Writes(cr.Match{}))
}

// RegisterBasic : register the OTP to the RESTFul API container
func (u OtpRestful) RegisterBasic(container *restful.Container) {
	servicePath = cr.ServicePathPrefix + cr.Version + otpPrefix

	service := new(restful.WebService)
	service.
		Path(servicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//.Doc("One Time Password")

	u.setRoute(service)
	container.Add(service)
}
