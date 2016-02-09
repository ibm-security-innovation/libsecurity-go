package libsecurityRestful

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/emicklei/go-restful"
	am "github.com/ibm-security-innovation/libsecurity-go/accounts"
	app "github.com/ibm-security-innovation/libsecurity-go/app/token"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

const (
	stPrefix  = "/libsecurity"
	storePath = "/store"
	loadPath  = "/load"

	userIDParam = "user-name"
)

var (
	servicePath  string
	toFilterFlag = true

	checkSecretStrength = true // Allow only strength secrets
)

// LibsecurityRestful : The LibsecurityRestful structure
type LibsecurityRestful struct {
	UsersList     *en.EntityManager
	verifyKey     *rsa.PublicKey
	loginKey      []byte
	SignKey       *rsa.PrivateKey
	SecureStorage *ss.SecureStorage
}

func init() {
	initCommandToPath()
}

// NewLibsecurityRestful : return a pointer to the LibsecurityRestful structure
func NewLibsecurityRestful() *LibsecurityRestful {
	return &LibsecurityRestful{}
}

// SetToFilterFlag : set the filter flag state
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
	isPrivilegeOk, err := app.IsPrivilegeOk(tokenStr, userPermission, getIPAddress(req), l.verifyKey)
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

// SuperUserFilter : Verify that the commands is called by user with super user privilege
func (l LibsecurityRestful) SuperUserFilter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	if l.verifyUserPermissions(req, resp, chain, am.SuperUserPermission) == true {
		chain.ProcessFilter(req, resp)
	}
}

// SameUserFilter : Verify that the commands is called by a super user or the user itself
func (l LibsecurityRestful) SameUserFilter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	if l.toFilter() == false {
		chain.ProcessFilter(req, resp)
		return
	}

	name := req.PathParameter(userIDParam)
	logger.Trace.Println("SameUserFilter: user name:", name)
	tokenStr := l.getCookieAccessTokenValue(req)
	if tokenStr == "" {
		l.setError(resp, http.StatusMethodNotAllowed, fmt.Errorf("You need to authenticate first"))
		return
	}
	isUserMatch, err := app.IsItTheSameUser(tokenStr, name, getIPAddress(req), l.verifyKey)
	if err != nil {
		l.setError(resp, http.StatusMethodNotAllowed, err)
		return
	}
	isPrivilegeOk, _ := app.IsPrivilegeOk(tokenStr, am.SuperUserPermission, getIPAddress(req), l.verifyKey)
	if isPrivilegeOk == false && isUserMatch == false {
		tokenData, _ := app.ParseToken(tokenStr, getIPAddress(req), l.verifyKey)
		l.setError(resp, http.StatusMethodNotAllowed, fmt.Errorf("User '%v' is not permited to do the operation, only the same user or root can execute it", tokenData.UserName))
		return
	}
	chain.ProcessFilter(req, resp)
}

// VerifyToken : verify is the received token is legal and as expected
func (l LibsecurityRestful) VerifyToken(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	tokenStr := l.getCookieAccessTokenValue(req)
	if tokenStr == "" {
		l.setError(resp, http.StatusMethodNotAllowed, fmt.Errorf("You need to authenticate first"))
		return
	}
	_, err := app.ParseToken(tokenStr, getIPAddress(req), l.verifyKey)
	if err != nil {
		l.setError(resp, http.StatusMethodNotAllowed, err)
		return
	}
	chain.ProcessFilter(req, resp)
}

// SetData : initialize the LibsecurityRestful structure
func (l *LibsecurityRestful) SetData(el *en.EntityManager, loginKeyVal []byte, verifyKeyval *rsa.PublicKey, signKeyVal *rsa.PrivateKey, secureStorage *ss.SecureStorage) {
	l.UsersList = el
	l.loginKey = loginKeyVal
	l.verifyKey = verifyKeyval
	l.SignKey = signKeyVal
	l.SecureStorage = secureStorage
}

func (l LibsecurityRestful) getURLPath(request *restful.Request, name string) cr.URL {
	return cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
}

func (l *LibsecurityRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (l LibsecurityRestful) restGetVersion(request *restful.Request, response *restful.Response) {
	response.WriteHeaderAndEntity(http.StatusOK, cr.StringMessage{Str: GetVersion()})
}

func (l LibsecurityRestful) restStoreData(request *restful.Request, response *restful.Response) {
	// old use var filePath cr.StringMessage
	var fileData cr.SecureFile

	err := request.ReadEntity(&fileData)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return
	}
	err = l.UsersList.StoreInfo(fileData.FilePath, []byte(fileData.Secret), checkSecretStrength)
	if err != nil {
		l.setError(response, http.StatusInternalServerError, err)
		return
	}
	response.WriteHeaderAndEntity(http.StatusOK, fileData.FilePath)
}

func (l LibsecurityRestful) restLoadData(request *restful.Request, response *restful.Response) {
	// old use var fileData cr.StringMessage
	var fileData cr.SecureFile

	err := request.ReadEntity(&fileData)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return
	}
	err = en.LoadInfo(fileData.FilePath, []byte(fileData.Secret), l.UsersList)
	if err != nil {
		l.setError(response, http.StatusInternalServerError, err)
		return
	}
	response.WriteHeaderAndEntity(http.StatusCreated, fileData.FilePath)
}

func getIPAddress(request *restful.Request) string {
	return strings.Split(request.Request.RemoteAddr, ":")[0]
}
