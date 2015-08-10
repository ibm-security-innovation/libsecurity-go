package libsecurity_restful

import (
	"fmt"
	"sync"

	//	en "ibm-security-innovation/libsecurity-go/entity"
	"github.com/emicklei/go-restful"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
)

const (
	handleFileCommand = iota
	handleCommand
)

var (
	Version    string = "2.2"
	MinVersion string = ".0008"

	urlCommands = make(cr.CommandToPath)

	commandsToPath = []cr.ComamndsToPath{
		{handleFileCommand, "%v"},
		{handleCommand, "%v"},
	}

	lock sync.Mutex
)

/* old use
type Libsecurity struct {
	UsersList *en.EntityManager
	//	appAclPermissions *appAcl.AppPermissionsS
}

func NewLibsecurity() *Libsecurity {
	st := Libsecurity{nil}
	return &st
}

func (s *LibsecurityRestful) SetData(el *en.EntityManager) {
	s.UsersList = el
}
*/

func GetVersion() string {
	return fmt.Sprintf("%s:%s%s", "Security Tool version", Version, MinVersion)
}

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

func (s LibsecurityRestful) loadStroreRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleFileCommand], StorePath)
	service.Route(service.PUT(str).
		Filter(s.SuperUserFilter).
		To(s.restStoreData).
		Doc("Store Security Tool data to file").
		Operation("updateLibsecurityDataFile").
		Reads(cr.SecureFile{}).
		Writes(cr.StringMessage{}))

	str = fmt.Sprintf(urlCommands[handleFileCommand], LoadPath)
	service.Route(service.PATCH(str).
		Filter(s.SuperUserFilter).
		To(s.restLoadData).
		Doc("Read Security Tool data from file").
		Operation("loadLibsecurityDataFile").
		Reads(cr.SecureFile{}))
}

func (s LibsecurityRestful) versionRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleCommand], cr.VersionPath)
	service.Route(service.GET(str).
		//		Filter(s.SuperUserFilter).
		To(s.restGetVersion).
		Doc("Get Security Tool version").
		Operation("getLibsecurityVersion").
		Writes(cr.StringMessage{}))
}

func (s LibsecurityRestful) RegisterBasic(container *restful.Container) {
	ServicePath = cr.ServicePathPrefix + cr.Version + StPrefix

	service := new(restful.WebService)
	service.
		Path(ServicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON).
		Doc("The Security Tool")

	s.loadStroreRoute(service)
	s.versionRoute(service)
	container.Add(service)
}
