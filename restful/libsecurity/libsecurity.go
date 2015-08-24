package main

import (
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emicklei/go-restful"
	"github.com/emicklei/go-restful/swagger"
	app "ibm-security-innovation/libsecurity-go/app/token"
	en "ibm-security-innovation/libsecurity-go/entity"
	logger "ibm-security-innovation/libsecurity-go/logger"
	"ibm-security-innovation/libsecurity-go/restful/accounts_restful"
	"ibm-security-innovation/libsecurity-go/restful/acl_restful"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	en_restful "ibm-security-innovation/libsecurity-go/restful/entity_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
	"ibm-security-innovation/libsecurity-go/restful/ocra_restful"
	"ibm-security-innovation/libsecurity-go/restful/otp_restful"
	"ibm-security-innovation/libsecurity-go/restful/password_restful"
	"ibm-security-innovation/libsecurity-go/restful/storage_restful"
	ss "ibm-security-innovation/libsecurity-go/storage"
)

const (
	amToken            = "accountManager"
	umToken            = "um"
	aclToken           = "acl"
	appAclToken        = "appAcl"
	otpToken           = "otp"
	ocraToken          = "ocra"
	passwordToken      = "password"
	secureStorageToken = "secureStorage"

	fullToken  = "full"
	basicToken = "basic"
	noneToken  = "none"

	HTTPS_STR = "https"
)

var (
	ConfigOptions []string

	verifyKey                                   *rsa.PublicKey
	signKey                                     *rsa.PrivateKey
	loginKey                                    []byte
	host, protocol, sslServerCert, sslServerKey *string
	generateJsonFlag                            *bool
)

type ConfigS map[string]string

func usage() {
	_, file := filepath.Split(os.Args[0])
	fmt.Fprintf(os.Stderr, "usage: %v.go\n", file)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nConfiguration file tokens are: %v\n", ConfigOptions)
	fmt.Fprintf(os.Stderr, "Options to configure: ('%v', '%v')\n", basicToken, fullToken)
	fmt.Fprintf(os.Stderr, "Note: The option '%v' is relevant only for %v\n", fullToken, amToken)
	os.Exit(2)
}

func init() {
	cr.ServicePathPrefix = "/forewind/app"
	ConfigOptions = []string{amToken, umToken, aclToken, appAclToken, otpToken, ocraToken, passwordToken, secureStorageToken}
	protocol = flag.String("protocol", "https", "Using protocol: http ot https")
	host = flag.String("host", "localhost:8080", "Listening host")
	generateJsonFlag = flag.Bool("generate", false, "generate static json")
	sslServerCert = flag.String("server-cert", "./dist/server.crt", "SSL server certificate file path for https")
	sslServerKey = flag.String("server-key", "./dist/server.key", "SSL server key file path for https")
}

func runRestApi(wsContainer *restful.Container) {
	config := swagger.Config{
		WebServices:     wsContainer.RegisteredWebServices(),
		WebServicesUrl:  "/", // host + port,
		ApiPath:         "/forewind/security.json",
		SwaggerPath:     "/forewind/doc/",
		SwaggerFilePath: "./dist",
		// TODO set it Title:           "libsecurity-go",
		// TODO set it Description:     "The libsecurity-go tool is for",
	}

	swagger.RegisterSwaggerService(config, wsContainer)
	if *generateJsonFlag {
		go generateJson(config.ApiPath, config.SwaggerFilePath+"/")
	}
	log.Printf("start listening on %v", *host)
	var err error
	if strings.HasPrefix(strings.ToLower(*protocol), HTTPS_STR) {
		err = http.ListenAndServeTLS(*host, *sslServerCert, *sslServerKey, wsContainer)
	} else {
		err = http.ListenAndServe(*host, wsContainer)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func readConfigFile(configFile string) (ConfigS, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var configData ConfigS
	err = json.Unmarshal(data, &configData)
	if err != nil {
		return nil, err
	}
	logger.Trace.Printf("The config data: %v", configData)
	return configData, nil
}

func registerComponents(configFile string, secureKeyFilePath string, privateKeyFilePath string, usersDataPath string) {
	conf, err := readConfigFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error while reading configuration file '%v', error: %v\n", configFile, err)
		os.Exit(1)
	}
	wsContainer := restful.NewContainer()
	usersList := en.New()

	//	amUsers := am.NewAmUsersList()
	signKey, verifyKey = app.TokenSetUp(privateKeyFilePath)
	loginKey = ss.GetSecureKey(secureKeyFilePath)

	st := libsecurity_restful.NewLibsecurityRestful()
	st.SetData(usersList, loginKey, verifyKey, signKey, nil)

	l := accounts_restful.NewAmRestful()
	l.SetData(st)
	if conf[amToken] == fullToken {
		l.RegisterFull(wsContainer)
	} else { // login is mandatory
		l.RegisterBasic(wsContainer)
	}

	um := en_restful.NewEnRestful()
	um.SetData(st)
	if conf[umToken] != noneToken {
		um.RegisterBasic(wsContainer)
	}

	a := acl_restful.NewAclRestful()
	a.SetData(st)
	if conf[aclToken] == basicToken || conf[appAclToken] == basicToken {
		a.RegisterBasic(wsContainer)
	}

	p := otp_restful.NewOtpRestful()
	p.SetData(st)
	if conf[otpToken] == basicToken {
		p.RegisterBasic(wsContainer)
	}

	o := ocra_restful.NewOcraRestful()
	o.SetData(st)
	if conf[ocraToken] == basicToken {
		o.RegisterBasic(wsContainer)
	}

	pwd := password_restful.NewPwdRestful()
	pwd.SetData(st)
	if conf[passwordToken] == basicToken {
		pwd.RegisterBasic(wsContainer)
	}

	ss := storage_restful.NewSsRestful()
	ss.SetData(st)
	if conf[secureStorageToken] == basicToken {
		ss.RegisterBasic(wsContainer)
	}

	st.RegisterBasic(wsContainer)

	err = en.LoadInfo(usersDataPath, loginKey, usersList)
	if err != nil {
		fmt.Println("Load info error:", err)
	}
	runRestApi(wsContainer)
}

func generateJson(path string, distPath string) {
	var obj map[string]interface{}
	baseUrl := fmt.Sprintf("%v://%v%v", *protocol, *host, path)
	fileFmt := "%v/%v"

	time.Sleep(100 * time.Millisecond)
	_, jsonD, _ := cr.HttpDataMethod(cr.GET_STR, baseUrl, "")
	err := json.Unmarshal([]byte(jsonD), &obj)
	if err != nil {
		log.Fatal(err)
	}
	var prefix, p1, file string
	for i, v := range obj["apis"].([]interface{}) {
		casted := v.(map[string]interface{})
		url1 := fmt.Sprintf("%v%v", baseUrl, casted["path"])
		_, u, _ := cr.HttpDataMethod(cr.GET_STR, url1, "")
		p1, file = filepath.Split(fmt.Sprintf("%v", casted["path"]))
		if i == 0 {
			prefix = strings.Replace(p1, "/", distPath, 1)
			err := os.MkdirAll(prefix, 0777)
			if err != nil {
				log.Fatalf("Fatal error while generating static JSON path: %v", err)
			}
		}
		ioutil.WriteFile(fmt.Sprintf(fileFmt, prefix, file), []byte(u), 0777)
	}
	_, file = filepath.Split(path)
	prefix1 := strings.Replace(p1, "/", "/../", 1)
	obj["apiVersion"] = "2.02"
	a := obj["info"].(map[string]interface{})
	a["title"] = "Libsecurity API"
	j, _ := json.Marshal(obj)
	newS := strings.Replace(string(j), p1, prefix1, -1)
	ioutil.WriteFile(fmt.Sprintf(fileFmt, distPath, file), []byte(newS), 0777)
}

func main() {
	privateKeyFilePath := flag.String("rsa-private", "./dist/key.private", "RSA private key file path")
	secureKeyFilePath := flag.String("secure-key", "./dist/secureKey", "password to encrypt the secure storage")
	usersDataPath := flag.String("storage-file", "./dist/data.txt", "persistence storage file")
	configFile := flag.String("config-file", "./config.json", "Configuration information file")
	flag.Parse()
	if flag.NArg() > 0 {
		usage()
	}
	registerComponents(*configFile, *secureKeyFilePath, *privateKeyFilePath, *usersDataPath)
}
