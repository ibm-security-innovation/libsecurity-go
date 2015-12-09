package entity_restful

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	stc "github.com/ibm-security-innovation/libsecurity-go/defs"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common_restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	UmPrefix          = "/entity"
	UsersPath         = "/users"
	GroupsPath        = "/groups"
	ResourcesPath     = "/resources"
	groupIdToken      = "groups"
	groupIdParam      = "group-name"
	groupIdComment    = "identifier of the group"
	userIdToken       = "users"
	userIdParam       = "user-name"
	resourceIdParam   = "resource-name"
	userIdComment     = "identifier of the user"
	resourceIdComment = "identifier of the resource"

	originToken = "Origin"
)

var (
	EnServicePath       string //  = cr.ServicePathPrefix + "/um"
	UsersServicePath    string // = EnServicePath + UsersPath
	GroupServicePath    string // = EnServicePath + GroupsPath
	ResourceServicePath string // = EnServicePath + ResourcePath
)

type enRestful struct {
	st *libsecurity_restful.LibsecurityRestful
}

func init() {
	EnServicePath = cr.ServicePathPrefix + UmPrefix
	UsersServicePath = EnServicePath + UsersPath
	GroupServicePath = EnServicePath + GroupsPath
	ResourceServicePath = EnServicePath + ResourcesPath

	initCommandToPath()
}

func NewEnRestful() *enRestful {
	return &enRestful{}
}

func (l *enRestful) SetData(stR *libsecurity_restful.LibsecurityRestful) {
	l.st = stR
}

func (g enRestful) getGroupUrlPath(request *restful.Request, name string) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v%v/%v", EnServicePath, GroupsPath, name)}
}

func (g enRestful) getUserUrlPath(request *restful.Request, name string) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v%v/%v", EnServicePath, UsersPath, name)}
}

func (g enRestful) getResourceUrlPath(request *restful.Request, name string) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v%v/%v", EnServicePath, ResourcesPath, name)}
}

func (g enRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (g *enRestful) restCreateGroup(request *restful.Request, response *restful.Response) {
	groupId := request.PathParameter(groupIdParam)
	err := g.st.UsersList.AddGroup(groupId)
	if err != nil {
		g.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(g.getGroupUrlPath(request, groupId))
}

func (g enRestful) getAllGroups() []string {
	var gList []string
	for name, _ := range g.st.UsersList.Groups {
		gList = append(gList, name)
	}
	return gList
}

func (g enRestful) restRemoveAllGroups(request *restful.Request, response *restful.Response) {
	gList := g.getAllGroups()
	for _, name := range gList {
		g.st.UsersList.RemoveGroup(name)
	}
	response.WriteHeader(http.StatusNoContent)
}

func (g enRestful) restGetGroup(request *restful.Request, response *restful.Response) {
	groupId := request.PathParameter(groupIdParam)
	group, exist := g.st.UsersList.Groups[groupId]
	if exist == false {
		g.setError(response, http.StatusNotFound, fmt.Errorf("Group "+groupId+" could not be found."))
		return
	}
	response.WriteEntity(group)
}

func (g *enRestful) restRemoveGroup(request *restful.Request, response *restful.Response) {
	groupId := request.PathParameter(groupIdParam)
	err := g.st.UsersList.RemoveGroup(groupId)
	if err != nil {
		g.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (g *enRestful) restAddUserToGroup(request *restful.Request, response *restful.Response) {
	groupId := request.PathParameter(groupIdParam)
	userId := request.PathParameter(userIdParam)
	err := g.st.UsersList.AddUserToGroup(groupId, userId)
	if err != nil {
		g.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(g.getGroupUrlPath(request, fmt.Sprintf("%v/%v/%v/%v", groupIdToken, groupId, userIdToken, userId)))
}

func (g *enRestful) restRemoveUserFromGroup(request *restful.Request, response *restful.Response) {
	groupId := request.PathParameter(groupIdParam)
	userId := request.PathParameter(userIdParam)
	err := g.st.UsersList.RemoveUserFromGroup(groupId, userId)
	if err != nil {
		g.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (u *enRestful) restCreateUser(request *restful.Request, response *restful.Response) {
	id := request.PathParameter(userIdParam)
	err := u.st.UsersList.AddUser(id)
	if err != nil {
		u.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(u.getUserUrlPath(request, id))
}

func (u enRestful) restGetEntityManager(request *restful.Request, response *restful.Response) {
	response.WriteEntity(u.st.UsersList)
}

func (u enRestful) restGetUser(request *restful.Request, response *restful.Response) {
	id := request.PathParameter(userIdParam)
	user, exist := u.st.UsersList.Users[id]
	if exist == false {
		u.setError(response, http.StatusNotFound, fmt.Errorf("User "+id+" could not be found."))
		return
	}
	response.WriteEntity(user)
}

func (u *enRestful) restRemoveAllUsers(request *restful.Request, response *restful.Response) {
	for name, _ := range u.st.UsersList.Users {
		if name == stc.RootUserName || name == stc.AclAllEntryName {
			continue
		}
		u.st.UsersList.RemoveUser(name)
	}
	response.WriteHeader(http.StatusNoContent)
}

func (u *enRestful) restRemoveUser(request *restful.Request, response *restful.Response) {
	id := request.PathParameter(userIdParam)
	err := u.st.UsersList.RemoveUser(id)
	if err != nil {
		u.setError(response, http.StatusNotFound, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (u enRestful) getUserByUserId(request *restful.Request, response *restful.Response) (*en.User, string) {
	userId := request.PathParameter(userIdParam)
	user, exist := u.st.UsersList.Users[userId]
	if exist == false {
		u.setError(response, http.StatusNotFound, fmt.Errorf("Error: user: '%v' can't be found", userId))
		return nil, userId
	}
	return user, userId
}

func (u *enRestful) restCreateResource(request *restful.Request, response *restful.Response) {
	id := request.PathParameter(resourceIdParam)
	err := u.st.UsersList.AddResource(id)
	if err != nil {
		u.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(u.getResourceUrlPath(request, id))
}

func (u enRestful) restGetResource(request *restful.Request, response *restful.Response) {
	id := request.PathParameter(resourceIdParam)
	user, exist := u.st.UsersList.Resources[id]
	if exist == false {
		u.setError(response, http.StatusNotFound, fmt.Errorf("Resource "+id+" could not be found."))
		return
	}
	response.WriteEntity(user)
}

func (u *enRestful) restRemoveAllResources(request *restful.Request, response *restful.Response) {
	for name, _ := range u.st.UsersList.Resources {
		u.st.UsersList.RemoveResource(name)
	}
	response.WriteHeader(http.StatusNoContent)
}

func (u *enRestful) restRemoveResource(request *restful.Request, response *restful.Response) {
	id := request.PathParameter(resourceIdParam)
	err := u.st.UsersList.RemoveResource(id)
	if err != nil {
		u.setError(response, http.StatusNotFound, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}
