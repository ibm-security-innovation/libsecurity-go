package accountsRestful

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/emicklei/go-restful"
	am "github.com/ibm-security-innovation/libsecurity-go/accounts"
	app "github.com/ibm-security-innovation/libsecurity-go/app/token"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	"github.com/ibm-security-innovation/libsecurity-go/password"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
	"github.com/ibm-security-innovation/libsecurity-go/salt"
)

const (
	amPrefix        = "/account-manager"
	userPath        = "/user"
	usersPath       = "/users"
	verifyPath      = "/verify"
	logoutPath      = "/logout"
	pwdPath         = "password"
	privilegePath   = "privilege"
	userIDParam     = "user-name"
	userNameComment = "user name"

	saltLen int = 20

	cookieExpirationDurationMinutes = 30
)

var (
	servicePath           string // = cr.ServicePathPrefix + "/accountmanager"
	checkPasswordStrength = true // Allow only strength passwords
)

// AmRestful : Account structure
type AmRestful struct {
	st *libsecurityRestful.LibsecurityRestful
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

// NewAmRestful : return a pointer to the AmRestful structure
func NewAmRestful() *AmRestful {
	return &AmRestful{}
}

func init() {
	initCommandToPath()
}

// SetData : initialize the AccountsRestful structure
func (l *AmRestful) SetData(stR *libsecurityRestful.LibsecurityRestful) {
	l.st = stR
}

func (l AmRestful) getURLPath(request *restful.Request, name string) cr.URL {
	return cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
}

func (l AmRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	logger.Error.Printf("Set Error code: %v, error: %v", httpStatusCode, err)
	response.WriteErrorString(httpStatusCode, string(data))
}

func (l AmRestful) getPrivilege(request *restful.Request, response *restful.Response) *privilegeInfo {
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

func (l AmRestful) getPwd(request *restful.Request, response *restful.Response) *secretData {
	var pwd secretData

	err := request.ReadEntity(&pwd)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return nil
	}
	return &pwd
}

func (l AmRestful) getPrivilegePwd(request *restful.Request, response *restful.Response) *privilegePwd {
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
func (l AmRestful) restAm(request *restful.Request, response *restful.Response) {
	var tUserInfo pUserData

	err := request.ReadEntity(&tUserInfo)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return
	}
	userInfo := userData{tUserInfo.Name, []byte(tUserInfo.Password)}
	data, err := l.st.UsersList.GetEntityAccount(userInfo.Name, []byte(userInfo.Password))
	if err != nil {
		l.setError(response, http.StatusMethodNotAllowed, err)
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

func (l AmRestful) restLogout(request *restful.Request, response *restful.Response) {
	addLogoutCookie(response)
	response.WriteHeader(http.StatusNoContent)
}

func (l AmRestful) restVerifyToken(request *restful.Request, response *restful.Response) {
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(cr.StringMessage{Str: "Token OK"})
}

func (l AmRestful) restAddAm(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIDParam)

	privilege := l.getPrivilegePwd(request, response)
	if privilege == nil {
		return
	}
	saltStr, _ := salt.GetRandomSalt(saltLen)

	data, err := am.NewUserAm(privilege.Privilege, []byte(privilege.Password), saltStr, checkPasswordStrength)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return
	}
	err = l.st.UsersList.AddPropertyToEntity(name, defs.AmPropertyName, data)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(l.getURLPath(request, name))
}

func (l AmRestful) getAM(request *restful.Request, response *restful.Response, userName string) *am.AmUserInfo {
	data, err := cr.GetPropertyData(userName, defs.AmPropertyName, l.st.UsersList)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return nil
	}
	return data.(*am.AmUserInfo)
}

func (l AmRestful) restGetAm(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter(userIDParam)
	data := l.getAM(request, response, userName)
	if data == nil {
		return
	}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(data)
}

func (l AmRestful) restDeleteAM(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIDParam)
	if name == defs.RootUserName {
		l.setError(response, http.StatusBadRequest, fmt.Errorf("Error: root user can't be deleted"))
		return
	}
	err := l.st.UsersList.RemovePropertyFromEntity(name, defs.AmPropertyName)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (l AmRestful) restUpdatePrivilege(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter(userIDParam)

	if userName == defs.RootUserName {
		l.setError(response, http.StatusBadRequest, fmt.Errorf("Error: '%v' user privilege can't be changed", defs.RootUserName))
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
	response.WriteEntity(l.getURLPath(request, userName))
}

func (l AmRestful) restUpdatePwd(request *restful.Request, response *restful.Response) {
	var secrets cr.UpdateSecret

	err := request.ReadEntity(&secrets)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return
	}
	userName := request.PathParameter(userIDParam)
	data := l.getAM(request, response, userName)
	if data == nil {
		return
	}
	tPwd, err := salt.GenerateSaltedPassword([]byte(secrets.OldPassword), password.MinPasswordLength, password.MaxPasswordLength, data.Pwd.Salt, -1)
	oldPwd := password.GetHashedPwd(tPwd)
	err = data.UpdateUserPwd(userName, oldPwd, []byte(secrets.NewPassword), false)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(l.getURLPath(request, userName))
}

func (l AmRestful) restResetPwd(request *restful.Request, response *restful.Response) {
	userName := request.PathParameter(userIDParam)
	data := l.getAM(request, response, userName)
	if data == nil {
		return
	}
	pwd, err := data.ResetUserPwd(userName)
	if err != nil {
		l.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(cr.Secret{Secret: string(pwd)})
}
