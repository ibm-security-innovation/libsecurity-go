package storage_restful

import (
	"fmt"

	//	"github.com/emicklei/go-restful"
	"github.com/emicklei/go-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/accounts_restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/common_restful"
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
	amRestful   = accounts_restful.NewAmRestful()
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

func (s ssRestful) setRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleStorageCommand], StoragePath)
	service.Route(service.PUT(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restCreateSecureStorage).
		Doc("Create a new secure storage").
		Operation("CreateSecureStorage").
		Param(service.HeaderParameter(secretIdParam, secretComment).DataType("string")).
		Writes(common_restful.Url{}))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], StoragePath)
	service.Route(service.DELETE(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restDeleteSecureStorage).
		Doc("Remove the current secure storage").
		Param(service.HeaderParameter(secretIdParam, secretComment).DataType("string")).
		Operation("RemoveSecureStorage"))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], StoragePath)
	service.Route(service.GET(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restGetSecureStorage).
		Doc("Get a secure storage").
		Operation("getSecureStorage").
		Param(service.HeaderParameter(secretIdParam, secretComment).DataType("string")))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], StorageItemPath)
	service.Route(service.PATCH(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restAddItemToSecureStorage).
		Doc("Add a new item to the secure storage").
		Operation("addANewItemToTheSecureStorage").
		Param(service.HeaderParameter(secretIdParam, secretComment).DataType("string")).
		Reads(itemData{}).
		Writes(common_restful.Url{}))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], StorageItemPath)
	service.Route(service.GET(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restGetItemFromSecureStorage).
		Doc("Get an item from the secure storage").
		Operation("getAnItemFromTheSecureStorage").
		Param(service.HeaderParameter(secretIdParam, secretComment).DataType("string")).
		Param(service.HeaderParameter(keyIdParam, keyComment).DataType("string")).
		Writes(itemValue{}))

	str = fmt.Sprintf(urlCommands[handleStorageCommand], StorageItemPath)
	service.Route(service.DELETE(str).
		// no filter is needed, the filter is the secure key		Filter(s.st.SuperUserFilter).
		To(s.restDeleteItemFromSecureStorage).
		Doc("Delete item from a secure storage").
		Operation("deleteItemFromSecureStorage").
		Param(service.HeaderParameter(secretIdParam, secretComment).DataType("string")).
		Param(service.HeaderParameter(keyIdParam, keyComment).DataType("string")))
}

func (s ssRestful) RegisterBasic(container *restful.Container) {
	ServicePath = common_restful.ServicePathPrefix + common_restful.Version + SsPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON).
		Doc("Secure Storage")

	s.setRoute(service)
	container.Add(service)
}
