package storageRestful

import (
	"fmt"

	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
)

const (
	handleStorageCommand = iota
)

type commandToPath map[int]string

var (
	commandsToPath = []comamndsToPathS{
		{handleStorageCommand, "%v"},
	}
	urlCommands = make(commandToPath)
	// old use AmRestful   = accountsRestful.NewAmRestful()
)

type comamndsToPathS struct {
	command int
	path    string
}

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.command] = c.path
	}
}

func (s SRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleStorageCommand], storagePath)
	service.Route(service.PUT(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restCreateSecureStorage).
		Doc("Create a new secure storage").
		Operation("CreateSecureStorage").
		Param(service.HeaderParameter(secretIDParam, secretComment).DataType("string")).
		Writes(commonRestful.URL{}))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], storagePath)
	service.Route(service.DELETE(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restDeleteSecureStorage).
		Doc("Remove the current secure storage").
		Param(service.HeaderParameter(secretIDParam, secretComment).DataType("string")).
		Operation("RemoveSecureStorage"))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], storagePath)
	service.Route(service.GET(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restGetSecureStorage).
		Doc("Get a secure storage").
		Operation("getSecureStorage").
		Param(service.HeaderParameter(secretIDParam, secretComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], storageItemPath)
	service.Route(service.PATCH(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restAddItemToSecureStorage).
		Doc("Add a new item to the secure storage").
		Operation("addANewItemToTheSecureStorage").
		Param(service.HeaderParameter(secretIDParam, secretComment).DataType("string")).
		Reads(itemData{}).
		Writes(commonRestful.URL{}))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], storageItemPath)
	service.Route(service.GET(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restGetItemFromSecureStorage).
		Doc("Get an item from the secure storage").
		Operation("getAnItemFromTheSecureStorage").
		Param(service.HeaderParameter(secretIDParam, secretComment).DataType("string")).
		Param(service.HeaderParameter(keyIDParam, keyComment).DataType("string")).
		Writes(itemValue{}))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], storageItemPath)
	service.Route(service.DELETE(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restDeleteItemFromSecureStorage).
		Doc("Delete item from a secure storage").
		Operation("deleteItemFromSecureStorage").
		Param(service.HeaderParameter(secretIDParam, secretComment).DataType("string")).
		Param(service.HeaderParameter(keyIDParam, keyComment).DataType("string")))
}

// RegisterBasic : register the Secure Storage to the RESTFul API container
func (s SRestful) RegisterBasic(container *restful.Container) {
	servicePath = commonRestful.ServicePathPrefix + commonRestful.Version + sPrefix

	service := new(restful.WebService)
	service.
		Path(servicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON).
		Doc("Secure Storage")

	s.setRoute(service)
	container.Add(service)
}
