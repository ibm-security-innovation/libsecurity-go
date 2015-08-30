package storage_restful

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
	ss "ibm-security-innovation/libsecurity-go/storage"
)

const (
	SsPrefix        = "/securestorage"
	StoragePath     = "/storage"
	StorageItemPath = "/item"

	secretIdParam = "secret"
	secretComment = "secret val"
	keyIdParam    = "key-id"
	keyComment    = "key val"
)

var (
	ServicePath string // = cr.ServicePathPrefix + SsPrefix

	CheckSecretStrength = true // Allow only strength secrets
)

type itemData struct {
	Key   string
	Value string
}

type itemValue struct {
	Data string
}

type ssRestful struct {
	st *libsecurity_restful.LibsecurityRestful
}

func init() {
	initCommandToPath()
}

func NewSsRestful() *ssRestful {
	return &ssRestful{}
}

func (s *ssRestful) SetData(stR *libsecurity_restful.LibsecurityRestful) {
	s.st = stR
}

func (s ssRestful) getUrlPath(request *restful.Request) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v", ServicePath)}
}

func (s ssRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (s ssRestful) isSecureStorgaeValid(response *restful.Response) bool {
	if s.st.SecureStorage == nil {
		s.setError(response, http.StatusNotFound, fmt.Errorf("Error: Secure storage must be created first"))
		return false
	}
	return true
}

func (s ssRestful) isSecretMatch(request *restful.Request, response *restful.Response) bool {
	secret := request.HeaderParameter(secretIdParam)
	if s.st.SecureStorage.IsSecretMatch([]byte(secret)) == false {
		s.setError(response, http.StatusNotFound, fmt.Errorf("Error: The entered password doesn't match the secure storage password"))
		return false
	}
	return true
}

func (s *ssRestful) restCreateSecureStorage(request *restful.Request, response *restful.Response) {
	secret := request.HeaderParameter(secretIdParam)
	data, err := ss.NewStorage([]byte(secret), CheckSecretStrength)
	if err != nil {
		s.setError(response, http.StatusBadRequest, err)
		return
	}
	s.st.SecureStorage = data
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(s.getUrlPath(request))
}

func (s ssRestful) restDeleteSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecretMatch(request, response) == false {
		return
	}
	s.st.SecureStorage = nil
	response.WriteHeader(http.StatusNoContent)
}

func (s ssRestful) restGetSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecureStorgaeValid(response) == false {
		return
	}
	if s.isSecretMatch(request, response) == false {
		return
	}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(s.st.SecureStorage.GetDecryptStorageData())
}

func (s ssRestful) restAddItemToSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecureStorgaeValid(response) == false {
		return
	}
	if s.isSecretMatch(request, response) == false {
		return
	}
	var item itemData
	err := request.ReadEntity(&item)
	if err != nil {
		s.setError(response, http.StatusBadRequest, err)
		return
	}

	err = s.st.SecureStorage.AddItem(item.Key, item.Value)
	if err != nil {
		s.setError(response, http.StatusInternalServerError, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(s.getUrlPath(request))
}

func (s ssRestful) restGetItemFromSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecureStorgaeValid(response) == false {
		return
	}
	if s.isSecretMatch(request, response) == false {
		return
	}
	key := request.HeaderParameter(keyIdParam)

	val, err := s.st.SecureStorage.GetItem(key)
	if err != nil {
		s.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(itemValue{val})
}

func (s ssRestful) restDeleteItemFromSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecureStorgaeValid(response) == false {
		return
	}
	if s.isSecretMatch(request, response) == false {
		return
	}
	key := request.HeaderParameter(keyIdParam)
	err := s.st.SecureStorage.RemoveItem(key)
	if err != nil {
		s.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
