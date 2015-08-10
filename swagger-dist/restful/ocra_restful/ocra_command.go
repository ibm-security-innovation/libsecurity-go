package ocra_restful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	"ibm-security-innovation/libsecurity-go/ocra"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
)

const (
	handleUserCommand = iota
	handleUserUpdateCommand
	verifyUserIdentityCommand
)

var (
	commandsToPath = []cr.ComamndsToPath{
		{handleUserCommand, "%v/{%v}"},
		{handleUserUpdateCommand, "%v/{%v}/%v"},
		{verifyUserIdentityCommand, "%v/{%v}/%v"},
	}

	urlCommands = make(cr.CommandToPath)
)

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

func (o ocraRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIdParam)
	service.Route(service.PUT(str).
		Filter(o.st.SuperUserFilter).
		To(o.restAddOcra).
		Doc("Add OCRA").
		Operation("addOcra").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(OcraUserData{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIdParam)
	service.Route(service.GET(str).
		Filter(o.st.SameUserFilter).
		To(o.restGetOcra).
		Doc("Get OCRA").
		Operation("getOcra").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Writes(ocra.UserOcra{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIdParam)
	service.Route(service.DELETE(str).
		Filter(o.st.SuperUserFilter).
		To(o.restDeleteOcra).
		Doc("Remove OCRA").
		Operation("deleteOcra").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleUserUpdateCommand], usersPath, userIdParam, keyToken)
	service.Route(service.PATCH(str).
		Filter(o.st.SuperUserFilter).
		To(o.restUpdateOcraKey).
		Doc("Update OCRA secret key").
		Operation("updtaeKey").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(cr.Secret{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[handleUserUpdateCommand], usersPath, userIdParam, ocraSuiteToken)
	service.Route(service.PATCH(str).
		Filter(o.st.SameUserFilter).
		To(o.restUpdateOcraSuite).
		Doc("Update OCRA suite").
		Operation("updtaeOcraSuite").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(cr.StringMessage{}).
		Writes(cr.Url{}))

	str = fmt.Sprintf(urlCommands[verifyUserIdentityCommand], usersPath, userIdParam, verifyUserIdentityChallengeToken)
	service.Route(service.GET(str).
		To(o.restVerifyOcraUserIdentityChallenge).
		Doc("Verify the user identity using OCRA, one way").
		Operation("verifyUserIdentity").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Writes(OcraData{}))

	str = fmt.Sprintf(urlCommands[verifyUserIdentityCommand], usersPath, userIdParam, verifyUserIdentityOtpToken)
	service.Route(service.PUT(str).
		To(o.restVerifyOcraUserIdentityCheckOtp).
		Doc("Check the user OTP challenge response using OCRA").
		Operation("verifyUserIdentityOtp").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(OcraData{}).
		Writes(cr.Match{}))

	str = fmt.Sprintf(urlCommands[verifyUserIdentityCommand], usersPath, userIdParam, verifyUserIdentityMutualChallengeStep1Token)
	service.Route(service.PUT(str).
		To(o.restVerifyOcraUserIdentityMutualChallengeStep1).
		Doc("Verify the user identity using OCRA, mutual chalange, Step 1").
		Operation("verifyUserIdentityMutualChallenge").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(cr.StringMessage{}).
		Writes(OcraData{}))

	str = fmt.Sprintf(urlCommands[verifyUserIdentityCommand], usersPath, userIdParam, verifyUserIdentityMutualChallengeStep2Token)
	service.Route(service.PUT(str).
		To(o.restVerifyOcraUserIdentityMutualChallengeStep2).
		Doc("Verify the user identity using OCRA, mutual chalange, Step 2").
		Operation("verifyUserIdentityMutualChallenge").
		Param(service.PathParameter(userIdParam, userNameComment).DataType("string")).
		Reads(OcraData{}).
		Writes(cr.Match{}))
}

func (o ocraRestful) RegisterBasic(container *restful.Container) {
	ServicePath = cr.ServicePathPrefix + cr.Version + OcraPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//.Doc("OATH Challenge-Response Algorithm")

	o.setRoute(service)
	container.Add(service)
}
