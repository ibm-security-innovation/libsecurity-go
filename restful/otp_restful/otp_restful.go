package otp_restful

import (
	"encoding/json"
	"fmt"
	"net/http"

	// en "github.com/ibm-security-innovation/libsecurity-go/entity"
	"github.com/emicklei/go-restful"
	stc "github.com/ibm-security-innovation/libsecurity-go/defs"
	"github.com/ibm-security-innovation/libsecurity-go/otp"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common_restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	OtpPrefix = "/otp"
	UsersPath = "/users"

	userIdParam         = "user-name"
	userNameComment     = "user name"
	blockedStateToken   = "blocked-state"
	blockedStateParam   = "blocked-state"
	verifyHotpTypeParam = "verify-hotp"
	verifyTotpTypeParam = "verify-totp"

	originToken = "Origin"

	trueStr  = "true"
	falseStr = "false"

	blockedStr    = "blocked"
	notblockedStr = "not blocked"
)

var (
	ServicePath         string // = cr.ServicePathPrefix + OtpPrefix
	CheckSecretStrength = true // Allow only strength passwords
)

type otpRestful struct {
	st *libsecurity_restful.LibsecurityRestful
}

type userState struct {
	Blocked bool
}

func init() {
	initCommandToPath()
}

func NewOtpRestful() *otpRestful {
	return &otpRestful{}
}

func (u *otpRestful) SetData(stR *libsecurity_restful.LibsecurityRestful) {
	u.st = stR
}

func (u otpRestful) getUrlPath(request *restful.Request, name string) cr.Url {
	//	return cr.Url{Url: fmt.Sprintf("%v%v/%v", request.Request.Header.Get(originToken), ServicePath, name)}
	return cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
}

func (u otpRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (u otpRestful) getOtp(request *restful.Request, response *restful.Response) *otp.OtpUser {
	userName := request.PathParameter(userIdParam)
	data, err := cr.GetPropertyData(userName, stc.OtpPropertyName, u.st.UsersList)
	if err != nil {
		u.setError(response, http.StatusNotFound, err)
		return nil
	}
	return data.(*otp.OtpUser)
}

func (u otpRestful) restAddOtp(request *restful.Request, response *restful.Response) {
	var secret cr.Secret
	name := request.PathParameter(userIdParam)

	err := request.ReadEntity(&secret)
	if err != nil {
		u.setError(response, http.StatusBadRequest, err)
		return
	}
	data, err := otp.NewSimpleOtpUser([]byte(secret.Secret), CheckSecretStrength)
	if err != nil {
		u.setError(response, http.StatusBadRequest, err)
		return
	}
	err = u.st.UsersList.AddPropertyToEntity(name, stc.OtpPropertyName, data)
	if err != nil {
		u.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(u.getUrlPath(request, name))
}

func (u otpRestful) restGetOtp(request *restful.Request, response *restful.Response) {
	data := u.getOtp(request, response)
	if data == nil {
		return
	}
	response.WriteEntity(data)
	response.WriteHeader(http.StatusOK)
}

func (u otpRestful) restDeleteOtp(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIdParam)
	err := u.st.UsersList.RemovePropertyFromEntity(name, stc.OtpPropertyName)
	if err != nil {
		u.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (u otpRestful) restIsOtpBlocked(request *restful.Request, response *restful.Response) {
	var state userState

	data := u.getOtp(request, response)
	if data == nil {
		return
	}
	ok, err := data.IsOtpUserBlocked()
	state.Blocked = ok
	if err != nil {
		u.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteEntity(state)
	response.WriteHeader(http.StatusOK)
}

func (u otpRestful) restSetOtpBlockedState(request *restful.Request, response *restful.Response) {
	var blockedState userState
	name := request.PathParameter(userIdParam)
	err := request.ReadEntity(&blockedState)
	if err != nil {
		u.setError(response, http.StatusBadRequest, err)
		return
	}
	data := u.getOtp(request, response)
	if data == nil {
		return
	}
	err = data.SetOtpUserBlockedState(blockedState.Blocked)
	if err != nil {
		u.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteEntity(u.getUrlPath(request, name))
	response.WriteHeader(http.StatusOK)
}

func (u otpRestful) getExpectedCodes(request *restful.Request, response *restful.Response) string {
	var secret cr.Secret
	data := u.getOtp(request, response)
	if data == nil {
		return ""
	}
	err := request.ReadEntity(&secret)
	if err != nil {
		u.setError(response, http.StatusBadRequest, err)
		return ""
	}
	valHot, _ := data.BaseHotp.AtCount(data.BaseHotp.Count)
	valTot, _ := data.BaseTotp.Now()
	return fmt.Sprintf("Expected Hotp code: %v, Count: %v, Expected Totp code: %v",
		valHot, data.BaseHotp.Count, valTot)
}

func (u otpRestful) restVerifyOtpHotpUserCode(request *restful.Request, response *restful.Response) {
	u.verifyUserOtp(request, response, otp.HotpType)
}

func (u otpRestful) restVerifyOtpTotpUserCode(request *restful.Request, response *restful.Response) {
	u.verifyUserOtp(request, response, otp.TotpType)
}

func (u otpRestful) verifyUserOtp(request *restful.Request, response *restful.Response, otpType otp.OtpType) {
	var secret cr.Secret

	err := request.ReadEntity(&secret)
	if err != nil {
		u.setError(response, http.StatusBadRequest, err)
		return
	}
	data := u.getOtp(request, response)
	if data == nil {
		return
	}
	ok, err := data.VerifyOtpUserCode(secret.Secret, otpType)
	res := cr.Match{Match: ok, Message: cr.NoMessageStr}
	if ok == false && err != nil {
		res.Message = fmt.Sprintf("%v", err)
	}
	response.WriteEntity(res)
	response.WriteHeader(http.StatusOK)
}
