package libsecurityRestful

import (
	"fmt"
	"sync"

	"github.com/emicklei/go-restful"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
)

const (
	handleFileCommand = iota
	handleCommand
)

var (
	// Version : the libsecurity version
	Version = "2.2"
	// MinVersion : the libsecurity sub version
	MinVersion = ".0008"

	urlCommands = make(cr.CommandToPath)

	commandsToPath = []cr.ComamndsToPath{
		{handleFileCommand, "%v"},
		{handleCommand, "%v"},
	}

	lock sync.Mutex
)

// GetVersion : return the libsecurity version as a string
func GetVersion() string {
	return fmt.Sprintf("%s:%s%s", "Security Tool version", Version, MinVersion)
}

func initCommandToPath() {
	for _, c := range commandsToPath {
		urlCommands[c.Command] = c.Path
	}
}

func (s LibsecurityRestful) loadStroreRoute(service *restful.WebService) {
	str := fmt.Sprintf(urlCommands[handleFileCommand], storePath)
	service.Route(service.PUT(str).
		Filter(s.SuperUserFilter).
		To(s.restStoreData).
		Doc("Store Security Tool data to file").
		Operation("updateLibsecurityDataFile").
		Reads(cr.SecureFile{}).
		Writes(cr.StringMessage{}))

	str = fmt.Sprintf(urlCommands[handleFileCommand], loadPath)
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

// RegisterBasic : register the libsecurity to the RESTFul API container
func (s LibsecurityRestful) RegisterBasic(container *restful.Container) {
	servicePath = cr.ServicePathPrefix + cr.Version + stPrefix
	service := new(restful.WebService)
	service.
		Path(servicePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON).
		Doc("The Security Tool")

	s.loadStroreRoute(service)
	s.versionRoute(service)
	container.Add(service)
}
