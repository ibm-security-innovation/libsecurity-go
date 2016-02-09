package storageRestful

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

const (
	sPrefix         = "/securestorage"
	storagePath     = "/storage"
	storageItemPath = "/item"

	secretIDParam = "secret"
	secretComment = "secret val"
	keyIDParam    = "key-id"
	keyComment    = "key val"
)

var (
	servicePath string // = cr.ServicePathPrefix + sPrefix

	checkSecretStrength = true // Allow only strength secrets
)

type itemData struct {
	Key   string
	Value string
}

type itemValue struct {
	Data string
}

// SRestful : Secure Storage restful structure
type SRestful struct {
	st *libsecurityRestful.LibsecurityRestful
}

func init() {
	initCommandToPath()
}

// NewSsRestful : return a pointer to the secure storage Restful structure
func NewSsRestful() *SRestful {
	return &SRestful{}
}

// SetData : initialize the Secure Storage Restful structure
func (s *SRestful) SetData(stR *libsecurityRestful.LibsecurityRestful) {
	s.st = stR
}

func (s SRestful) getURLPath(request *restful.Request) cr.URL {
	return cr.URL{URL: fmt.Sprintf("%v", servicePath)}
}

func (s SRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (s SRestful) isSecureStorgaeValid(response *restful.Response) bool {
	if s.st.SecureStorage == nil {
		s.setError(response, http.StatusNotFound, fmt.Errorf("Error: Secure storage must be created first"))
		return false
	}
	return true
}

func (s SRestful) isSecretMatch(request *restful.Request, response *restful.Response) bool {
	secret := request.HeaderParameter(secretIDParam)
	if s.st.SecureStorage.IsSecretMatch([]byte(secret)) == false {
		s.setError(response, http.StatusNotFound, fmt.Errorf("Error: The entered password doesn't match the secure storage password"))
		return false
	}
	return true
}

func (s *SRestful) restCreateSecureStorage(request *restful.Request, response *restful.Response) {
	secret := request.HeaderParameter(secretIDParam)
	data, err := ss.NewStorage([]byte(secret), checkSecretStrength)
	if err != nil {
		s.setError(response, http.StatusBadRequest, err)
		return
	}
	s.st.SecureStorage = data
	response.WriteHeaderAndEntity(http.StatusCreated, s.getURLPath(request))
}

func (s SRestful) restDeleteSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecretMatch(request, response) == false {
		return
	}
	s.st.SecureStorage = nil
	response.WriteHeader(http.StatusNoContent)
}

func (s SRestful) restGetSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecureStorgaeValid(response) == false {
		return
	}
	if s.isSecretMatch(request, response) == false {
		return
	}
	response.WriteHeaderAndEntity(http.StatusOK, s.st.SecureStorage.GetDecryptStorageData())
}

func (s SRestful) restAddItemToSecureStorage(request *restful.Request, response *restful.Response) {
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
	response.WriteHeaderAndEntity(http.StatusCreated, s.getURLPath(request))
}

func (s SRestful) restGetItemFromSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecureStorgaeValid(response) == false {
		return
	}
	if s.isSecretMatch(request, response) == false {
		return
	}
	key := request.HeaderParameter(keyIDParam)

	val, err := s.st.SecureStorage.GetItem(key)
	if err != nil {
		s.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeaderAndEntity(http.StatusOK, itemValue{val})
}

func (s SRestful) restDeleteItemFromSecureStorage(request *restful.Request, response *restful.Response) {
	if s.isSecureStorgaeValid(response) == false {
		return
	}
	if s.isSecretMatch(request, response) == false {
		return
	}
	key := request.HeaderParameter(keyIDParam)
	err := s.st.SecureStorage.RemoveItem(key)
	if err != nil {
		s.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
