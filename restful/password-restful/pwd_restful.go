package passwordRestful

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	"github.com/ibm-security-innovation/libsecurity-go/password"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
	"github.com/ibm-security-innovation/libsecurity-go/salt"
)

const (
	pwdPrefix        = "/password"
	usersPath        = "/users"
	userIDParam      = "user-name"
	userNameComment  = "user name"
	resetUserPwdPath = "reset"
)

var (
	servicePath string // = cr.ServicePathPrefix + pwdPrefix

	saltLen = 10

	checkPasswordStrength = true // Allow only strength passwords
)

// PwdRestful : Pwd restful structure
type PwdRestful struct {
	st      *libsecurityRestful.LibsecurityRestful
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

// NewPwdRestful : return a pointer to the PwdRestful structure
func NewPwdRestful() *PwdRestful {
	saltStr, _ := salt.GetRandomSalt(saltLen)
	return &PwdRestful{nil, saltStr}
}

// SetData : initialize the PwdRestful structure
func (p *PwdRestful) SetData(stR *libsecurityRestful.LibsecurityRestful) {
	p.st = stR
}

func (p PwdRestful) getURLPath(request *restful.Request, name string) cr.URL {
	return cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
}

func (p PwdRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (p PwdRestful) getPwdData(request *restful.Request, response *restful.Response) *password.UserPwd {
	userName := request.PathParameter(userIDParam)
	data, err := cr.GetPropertyData(userName, defs.PwdPropertyName, p.st.UsersList)
	if err != nil {
		p.setError(response, http.StatusNotFound, err)
		return nil
	}
	return data.(*password.UserPwd)
}

func (p PwdRestful) restAddPwd(request *restful.Request, response *restful.Response) {
	var secret secretData
	name := request.PathParameter(userIDParam)

	err := request.ReadEntity(&secret)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	data, err := password.NewUserPwd([]byte(secret.Password), p.saltStr, checkPasswordStrength)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	err = p.st.UsersList.AddPropertyToEntity(name, defs.PwdPropertyName, data)
	if err != nil {
		p.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(p.getURLPath(request, name))
}

func (p PwdRestful) restGetPwd(request *restful.Request, response *restful.Response) {
	data := p.getPwdData(request, response)
	if data == nil {
		return
	}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(data)
}

func (p PwdRestful) restDeletePwd(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIDParam)
	data := p.getPwdData(request, response)
	if data == nil {
		return
	}
	err := p.st.UsersList.RemovePropertyFromEntity(name, defs.PwdPropertyName)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (p PwdRestful) restUpdatePassword(request *restful.Request, response *restful.Response) {
	var secrets cr.UpdateSecret
	name := request.PathParameter(userIDParam)
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
	_, err = data.UpdatePassword(pass, []byte(secrets.NewPassword), checkPasswordStrength)
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(p.getURLPath(request, name))
}

func (p PwdRestful) restResetPassword(request *restful.Request, response *restful.Response) {
	data := p.getPwdData(request, response)
	if data == nil {
		return
	}
	newPwd, err := data.ResetPassword()
	if err != nil {
		p.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(secretData{string(newPwd)})
}

func (p PwdRestful) restVerifyPassword(request *restful.Request, response *restful.Response) {
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
