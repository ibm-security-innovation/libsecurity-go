package accounts_restful

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	am "ibm-security-innovation/libsecurity-go/accounts"
	app "ibm-security-innovation/libsecurity-go/app/token"
	// en "ibm-security-innovation/libsecurity-go/entity"
	"github.com/emicklei/go-restful"
	stc "ibm-security-innovation/libsecurity-go/defs"
	logger "ibm-security-innovation/libsecurity-go/logger"
	"ibm-security-innovation/libsecurity-go/password"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
	"ibm-security-innovation/libsecurity-go/salt"
)

const (
	AmPrefix        = "/account-manager"
	UserPath        = "/user"
	UsersPath       = "/users"
	VerifyPath      = "/verify"
	LogoutPath      = "/logout"
	PwdPath         = "password"
	PrivilegePath   = "privilege"
	userIdParam     = "user-name"
	userNameComment = "user name"

	SaltLen int = 20

	cookieExpirationDurationMinutes = 30
)

var (
	ServicePath string // = cr.ServicePathPrefix + "/accountmanager"
)

type amRestful struct {
	st *libsecurity_restful.LibsecurityRestful
}

type secretData struct {
	Password string
}

type userData struct {
	Name     string
	Password []byte
}

type pUserData struct {
	Name     string
	Password string
}

type privilegePwd struct {
	Password  string
	Privilege string
}

type privilegeInfo struct {
	Privilege string
}

func NewAmRestful() *amRestful {
	return &amRestful{}
}

func init() {
	initCommandToPath()
}

func (l *amRestful) SetData(stR *libsecurity_restful.LibsecurityRestful) {
	l.st = stR
}

func (l amRestful) getUrlPath(request *restful.Request, name string) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
}

func (l amRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	logger.Error.Printf("Set Error code: %v, error: %v", httpStatusCode, err)
	response.WriteErrorString(httpStatusCode, string(data))
}

func (l amRestful) getPrivilege(request *restful.Request, response *restful.Response) *privilegeInfo {
	var privilege privilegeInfo

	err := request.ReadEntity(&privilege)
	if err == nil {
		err = am.IsValidPrivilege(privilege.Privilege)
	}
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return nil
	}
	return &privilege
}

func (l amRestful) getPwd(request *restful.Request, response *restful.Response) *secretData {
	var pwd secretData

	err := request.ReadEntity(&pwd)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return nil
	}
	return &pwd
}

func (l amRestful) getPrivilegePwd(request *restful.Request, response *restful.Response) *privilegePwd {
	var privilegePwd privilegePwd

	err := request.ReadEntity(&privilegePwd)
	if err == nil {
		err = am.IsValidPrivilege(privilegePwd.Privilege)
	}
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return nil
	}
	return &privilegePwd
}

func addLoginCookie(response *restful.Response, tokenStr string) {
	expire := time.Now().Add(time.Minute * cookieExpirationDurationMinutes)
	str := fmt.Sprintf("%v=%v ; path=/ ; Expires %v", cr.AccessToken, tokenStr, expire.Format(time.UnixDate))
	response.AddHeader(cr.SetCookieStr, str)
}

func addLogoutCookie(response *restful.Response) {
	str := fmt.Sprintf("%v=%v ; path=/ ; expires=Thu, 01 Jan 1970 00:00:00 GMT", cr.AccessToken, "")
	response.AddHeader(cr.SetCookieStr, str)
}

// TODO should I force to do logout first
func (l amRestful) restAm(request *restful.Request, response *restful.Response) {
	var tUserInfo pUserData

	err := request.ReadEntity(&tUserInfo)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return
	}
	userInfo := userData{tUserInfo.Name, []byte(tUserInfo.Password)}
	data := l.getAM(request, response, userInfo.Name)
	if data == nil {
		return
	}
	err = data.IsPasswordMatch([]byte(userInfo.Password))
	if err != nil {
		l.setError(response, http.StatusMethodNotAllowed, fmt.Errorf("Error with the password for user '%v': %v", userInfo.Name, err))
		return
	}
	tokenStr, err := app.GenerateToken(userInfo.Name, data.Privilege, getIPAddress(request), l.st.SignKey)
	if err != nil {
		l.setError(response, http.StatusInternalServerError, err)
		return
	}
	logger.Info.Println("User:", userInfo.Name, "is authenticated")
	addLoginCookie(response, tokenStr)
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(cr.Match{Match: true, Message: fmt.Sprintf("User '%v' is authenticated", userInfo.Name)})
}

func getIPAddress(request *restful.Request) string {
	return strings.Split(request.Request.RemoteAddr, ":")[0]
}

func (l amRestful) restLogout(request *restful.Request, response *restful.Response) {
	addLogoutCookie(response)
	response.WriteHeader(http.StatusNoContent)
}

func (l amRestful) restVerifyToken(request *restful.Request, response *restful.Response) {
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(cr.StringMessage{Str: "Token OK"})
}

func (l amRestful) restAddAm(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIdParam)

	privilege := l.getPrivilegePwd(request, response)
	if privilege == nil {
		return
	}
	saltStr, _ := salt.GetRandomSalt(SaltLen)

	data, err := am.NewUserAm(privilege.Privilege, []byte(privilege.Password), saltStr)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return
	}
	err = l.st.UsersList.AddPropertyToEntity(name, stc.AmPropertyName, data)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(l.getUrlPath(request, name))
}

func (l amRestful) getAM(request *restful.Request, response *restful.Response, userName string) *am.AmUserInfo {
	data, err := cr.GetPropertyData(userName, stc.AmPropertyName, l.st.UsersList)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return nil
	}
	return data.(*am.AmUserInfo)
}

func (l amRestful) restGetAm(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter(userIdParam)
	data := l.getAM(request, response, userName)
	if data == nil {
		return
	}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(data)
}

func (l amRestful) restDeleteAM(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIdParam)
	if name == stc.RootUserName {
		l.setError(response, http.StatusBadRequest, fmt.Errorf("Error: root user can't be deleted"))
		return
	}
	err := l.st.UsersList.RemovePropertyFromEntity(name, stc.AmPropertyName)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (l amRestful) restUpdatePrivilege(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter(userIdParam)

	if userName == stc.RootUserName {
		l.setError(response, http.StatusBadRequest, fmt.Errorf("Error: '%v' user privilege can't be changed", stc.RootUserName))
		return
	}
	privilege := l.getPrivilege(request, response)
	if privilege == nil {
		return
	}
	data := l.getAM(request, response, userName)
	if data == nil {
		return
	}
	err := data.UpdateUserPrivilege(privilege.Privilege)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(l.getUrlPath(request, userName))
}

func (l amRestful) restUpdatePwd(request *restful.Request, response *restful.Response) {
	var secrets cr.UpdateSecret

	err := request.ReadEntity(&secrets)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return
	}
	userName := request.PathParameter(userIdParam)
	data := l.getAM(request, response, userName)
	if data == nil {
		return
	}
	tPwd, err := salt.GenerateSaltedPassword([]byte(secrets.OldPassword), password.MinPasswordLength, password.MaxPasswordLength, data.Pwd.Salt, -1)
	oldPwd := password.GetHashedPwd(tPwd)
	err = data.UpdateUserPwd(userName, oldPwd, []byte(secrets.NewPassword))
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(l.getUrlPath(request, userName))
}
