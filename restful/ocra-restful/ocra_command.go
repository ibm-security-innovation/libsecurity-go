package ocraRestful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/ocra"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
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

func (o OcraRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.PUT(str).
		Filter(o.st.SuperUserFilter).
		To(o.restAddOcra).
		Doc("Add OCRA").
		Operation("addOcra").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(ocraUserData{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.GET(str).
		Filter(o.st.SameUserFilter).
		To(o.restGetOcra).
		Doc("Get OCRA").
		Operation("getOcra").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Writes(ocra.UserOcra{}))

	str = fmt.Sprintf(urlCommands[handleUserCommand], usersPath, userIDParam)
	service.Route(service.DELETE(str).
		Filter(o.st.SuperUserFilter).
		To(o.restDeleteOcra).
		Doc("Remove OCRA").
		Operation("deleteOcra").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleUserUpdateCommand], usersPath, userIDParam, keyToken)
	service.Route(service.PATCH(str).
		Filter(o.st.SuperUserFilter).
		To(o.restUpdateOcraKey).
		Doc("Update OCRA secret key").
		Operation("updtaeKey").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(cr.Secret{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[handleUserUpdateCommand], usersPath, userIDParam, ocraSuiteToken)
	service.Route(service.PATCH(str).
		Filter(o.st.SameUserFilter).
		To(o.restUpdateOcraSuite).
		Doc("Update OCRA suite").
		Operation("updtaeOcraSuite").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(cr.StringMessage{}).
		Writes(cr.URL{}))

	str = fmt.Sprintf(urlCommands[verifyUserIdentityCommand], usersPath, userIDParam, verifyUserIdentityChallengeToken)
	service.Route(service.GET(str).
		To(o.restVerifyOcraUserIdentityChallenge).
		Doc("Verify the user identity using OCRA, one way").
		Operation("verifyUserIdentity").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Writes(ocraData{}))

	str = fmt.Sprintf(urlCommands[verifyUserIdentityCommand], usersPath, userIDParam, verifyUserIdentityOtpToken)
	service.Route(service.PUT(str).
		To(o.restVerifyOcraUserIdentityCheckOtp).
		Doc("Check the user OTP challenge response using OCRA").
		Operation("verifyUserIdentityOtp").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(ocraData{}).
		Writes(cr.Match{}))

	str = fmt.Sprintf(urlCommands[verifyUserIdentityCommand], usersPath, userIDParam, verifyUserIdentityMutualChallengeStep1Token)
	service.Route(service.PUT(str).
		To(o.restVerifyOcraUserIdentityMutualChallengeStep1).
		Doc("Verify the user identity using OCRA, mutual chalange, Step 1").
		Operation("verifyUserIdentityMutualChallenge").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(cr.StringMessage{}).
		Writes(ocraData{}))

	str = fmt.Sprintf(urlCommands[verifyUserIdentityCommand], usersPath, userIDParam, verifyUserIdentityMutualChallengeStep2Token)
	service.Route(service.PUT(str).
		To(o.restVerifyOcraUserIdentityMutualChallengeStep2).
		Doc("Verify the user identity using OCRA, mutual chalange, Step 2").
		Operation("verifyUserIdentityMutualChallenge").
		Param(service.PathParameter(userIDParam, userNameComment).DataType("string")).
		Reads(ocraData{}).
		Writes(cr.Match{}))
}

// RegisterBasic : register the OCRA to the RESTFul API container
func (o OcraRestful) RegisterBasic(container *restful.Container) {
	servicePath = cr.ServicePathPrefix + cr.Version + ocraPrefix

	service := new(restful.WebService)
	service.
		Path(servicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	//.Doc("OATH Challenge-Response Algorithm")

	o.setRoute(service)
	container.Add(service)
}
