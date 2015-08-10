package libsecurity_restful

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	am "ibm-security-innovation/libsecurity-go/accounts"
	app "ibm-security-innovation/libsecurity-go/app/token"
	en "ibm-security-innovation/libsecurity-go/entity"
	logger "ibm-security-innovation/libsecurity-go/logger"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	ss "ibm-security-innovation/libsecurity-go/storage"
)

const (
	StPrefix  = "/libsecurity"
	StorePath = "/store"
	LoadPath  = "/load"

	userIdParam = "user-name"
)

var (
	ServicePath string

	toFilterFlag bool = true
)

type LibsecurityRestful struct {
	UsersList     *en.EntityManager
	verifyKey     []byte
	loginKey      []byte
	SignKey       []byte
	SecureStorage *ss.SecureStorage
}

func init() {
	initCommandToPath()
}

func NewLibsecurityRestful() *LibsecurityRestful {
	return &LibsecurityRestful{}
}

func (l LibsecurityRestful) SetToFilterFlag(val bool) {
	toFilterFlag = val
	logger.Info.Println("Set toFilterFlag to:", toFilterFlag)
}

// Continue if we need to filter
func (l LibsecurityRestful) toFilter() bool {
	if toFilterFlag == false {
		logger.Info.Println("No filtering")
	}
	return toFilterFlag
}

func (l LibsecurityRestful) getCookieAccessTokenValue(req *restful.Request) string {
	vec := req.Request.Cookies()

	tokenStr := ""
	for _, c := range vec {
		if c.Name == cr.AccessToken {
			tokenStr = c.Value
		}
		logger.Trace.Println("cookie name:", c.Name, "value:", c.Value)
	}
	return tokenStr
}

func (l LibsecurityRestful) verifyUserPermissions(req *restful.Request, resp *restful.Response, chain *restful.FilterChain, userPermission string) bool {
	if l.toFilter() == false {
		return true
	}

	tokenStr := l.getCookieAccessTokenValue(req)
	if tokenStr == "" {
		l.setError(resp, http.StatusMethodNotAllowed, fmt.Errorf("You need to authenticate first"))
		return false
	}
	isPrivilegeOk, err := app.IsPrivilegeOk(tokenStr, userPermission, req.Request.RemoteAddr, l.verifyKey)
	if err != nil {
		l.setError(resp, http.StatusMethodNotAllowed, err)
		return false
	}
	if isPrivilegeOk == false {
		l.setError(resp, http.StatusMethodNotAllowed, fmt.Errorf("This command must be called by root user"))
		return false
	}
	return true
}

// Verify that the commands is called by user with super user privilege
func (l LibsecurityRestful) SuperUserFilter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	if l.verifyUserPermissions(req, resp, chain, am.SuperUserPermission) == true {
		chain.ProcessFilter(req, resp)
	}
}

// Verify that the commands is called by a super user or the user itself
func (l LibsecurityRestful) SameUserFilter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	if l.toFilter() == false {
		chain.ProcessFilter(req, resp)
		return
	}

	name := req.PathParameter(userIdParam)
	logger.Trace.Println("SameUserFilter: user name:", name)
	tokenStr := l.getCookieAccessTokenValue(req)
	if tokenStr == "" {
		l.setError(resp, http.StatusMethodNotAllowed, fmt.Errorf("You need to authenticate first"))
		return
	}
	isUserMatch, err := app.IsItTheSameUser(tokenStr, name, req.Request.RemoteAddr, l.verifyKey)
	if err != nil {
		l.setError(resp, http.StatusMethodNotAllowed, err)
		return
	}
	isPrivilegeOk, _ := app.IsPrivilegeOk(tokenStr, am.SuperUserPermission, req.Request.RemoteAddr, l.verifyKey)
	if isPrivilegeOk == false && isUserMatch == false {
		tokenData, _ := app.ParseToken(tokenStr, req.Request.RemoteAddr, l.verifyKey)
		l.setError(resp, http.StatusMethodNotAllowed, fmt.Errorf("User '%v' is not permited to do the operation, only the same user or root can execute it", tokenData.UserName))
		return
	}
	chain.ProcessFilter(req, resp)
}

func (l LibsecurityRestful) VerifyToken(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	tokenStr := l.getCookieAccessTokenValue(req)
	if tokenStr == "" {
		l.setError(resp, http.StatusMethodNotAllowed, fmt.Errorf("You need to authenticate first"))
		return
	}
	_, err := app.ParseToken(tokenStr, req.Request.RemoteAddr, l.verifyKey)
	if err != nil {
		l.setError(resp, http.StatusMethodNotAllowed, err)
		return
	}
	chain.ProcessFilter(req, resp)
}

func (s *LibsecurityRestful) SetData(el *en.EntityManager, loginKeyVal []byte, verifyKeyval []byte, signKeyVal []byte, secureStorage *ss.SecureStorage) {
	s.UsersList = el
	s.loginKey = loginKeyVal
	s.verifyKey = verifyKeyval
	s.SignKey = signKeyVal
	s.SecureStorage = secureStorage
}

func (s LibsecurityRestful) getUrlPath(request *restful.Request, name string) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
}

func (s *LibsecurityRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (s LibsecurityRestful) restGetVersion(request *restful.Request, response *restful.Response) {
	response.WriteEntity(cr.StringMessage{Str: GetVersion()})
}

func (s LibsecurityRestful) restStoreData(request *restful.Request, response *restful.Response) {
	// old use var filePath cr.StringMessage
	var fileData cr.SecureFile

	err := request.ReadEntity(&fileData)
	if err != nil {
		s.setError(response, http.StatusNotFound, err)
		return
	}
	err = s.UsersList.StoreInfo(fileData.FilePath, []byte(fileData.Secret))
	if err != nil {
		s.setError(response, http.StatusInternalServerError, err)
		return
	}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(fileData.FilePath)
}

func (s LibsecurityRestful) restLoadData(request *restful.Request, response *restful.Response) {
	// old use var fileData cr.StringMessage
	var fileData cr.SecureFile

	err := request.ReadEntity(&fileData)
	if err != nil {
		s.setError(response, http.StatusNotFound, err)
		return
	}
	err = en.LoadInfo(fileData.FilePath, []byte(fileData.Secret), s.UsersList)
	if err != nil {
		s.setError(response, http.StatusInternalServerError, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(fileData.FilePath)
}
