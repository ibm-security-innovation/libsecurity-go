package password_restful

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	stc "ibm-security-innovation/libsecurity-go/defs"
	"ibm-security-innovation/libsecurity-go/password"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
	"ibm-security-innovation/libsecurity-go/salt"
)

const (
	PwdPrefix        = "/password"
	UsersPath        = "/users"
	userIdParam      = "user-name"
	userNameComment  = "user name"
	ResetUserPwdPath = "reset"
)

var (
	ServicePath string // = cr.ServicePathPrefix + PwdPrefix

	saltLen int = 10
)

type pwdRestful struct {
	st      *libsecurity_restful.LibsecurityRestful
	saltStr []byte
}

type secretData struct {
	Password string
}

type userState struct {
	Blocked bool
}

func init() {
	initCommandToPath()
}

func NewPwdRestful() *pwdRestful {
	saltStr, _ := salt.GetRandomSalt(saltLen)
	return &pwdRestful{nil, saltStr}
}

func (p *pwdRestful) SetData(stR *libsecurity_restful.LibsecurityRestful) {
	p.st = stR
}

func (p pwdRestful) getUrlPath(request *restful.Request, name string) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
}

func (p pwdRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (p pwdRestful) getPwdData(request *restful.Request, response *restful.Response) *password.UserPwd {
	userName := request.PathParameter(userIdParam)
	data, err := cr.GetPropertyData(userName, stc.PwdPropertyName, p.st.UsersList)
	if err != nil {
		p.setError(response, http.StatusNotFound, err)
		return nil
	}
	return data.(*password.UserPwd)
}

func (p pwdRestful) restAddPwd(request *restful.Request, response *restful.Response) {
	var secret secretData
	name := request.PathParameter(userIdParam)

	err := request.ReadEntity(&secret)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	data, err := password.NewUserPwd([]byte(secret.Password), p.saltStr)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	err = p.st.UsersList.AddPropertyToEntity(name, stc.PwdPropertyName, data)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(p.getUrlPath(request, name))
}

func (p pwdRestful) restGetPwd(request *restful.Request, response *restful.Response) {
	data := p.getPwdData(request, response)
	if data == nil {
		return
	}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(data)
}

func (p pwdRestful) restDeletePwd(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIdParam)
	data := p.getPwdData(request, response)
	if data == nil {
		return
	}
	err := p.st.UsersList.RemovePropertyFromEntity(name, stc.PwdPropertyName)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (p pwdRestful) restUpdatePassword(request *restful.Request, response *restful.Response) {
	var secrets cr.UpdateSecret
	name := request.PathParameter(userIdParam)
	err := request.ReadEntity(&secrets)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	data := p.getPwdData(request, response)
	if data == nil {
		return
	}
	tPwd, _ := salt.GenerateSaltedPassword([]byte(secrets.OldPassword), password.MinPasswordLength, password.MaxPasswordLength, p.saltStr, -1)
	pass := password.GetHashedPwd(tPwd)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	_, err = data.UpdatePassword(pass, []byte(secrets.NewPassword))
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(p.getUrlPath(request, name))
}

func (p pwdRestful) restResetPassword(request *restful.Request, response *restful.Response) {
	data := p.getPwdData(request, response)
	if data == nil {
		return
	}
	newPwd, err := data.ResetPasword()
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(secretData{string(newPwd)})
}

func (p pwdRestful) restVerifyPassword(request *restful.Request, response *restful.Response) {
	var secret secretData
	err := request.ReadEntity(&secret)
	tPwd, _ := salt.GenerateSaltedPassword([]byte(secret.Password), password.MinPasswordLength, password.MaxPasswordLength, p.saltStr, -1)
	pass := password.GetHashedPwd(tPwd)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	data := p.getPwdData(request, response)
	if data == nil {
		return
	}
	err = data.IsPasswordMatch(pass)
	ok := true
	if err != nil {
		ok = false
	}
	res := cr.Match{Match: ok, Message: cr.NoMessageStr}
	if ok == false && err != nil {
		res.Message = fmt.Sprintf("%v", err)
	}
	response.WriteEntity(res)
	response.WriteHeader(http.StatusOK)
}
