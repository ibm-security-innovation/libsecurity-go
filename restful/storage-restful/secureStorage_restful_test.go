package storageRestful

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/emicklei/go-restful"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

const (
	host     = "http://localhost"
	port     = ":8082"
	listener = host + port

	secretCode = "aBCc1@234567890123456"
	emptyRes   = "{}"
)

type headerMapT map[string]string

var (
	resourcePath string // = listener + servicePath + storagePath
	itemPath     string // = listener + servicePath + storageItemPath

	baseHeaderInfo = make(headerMapT)
	stRestful      *libsecurityRestful.LibsecurityRestful
)

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)

	servicePath = cr.ServicePathPrefix + cr.Version + sPrefix
	resourcePath = listener + servicePath + storagePath
	itemPath = listener + servicePath + storageItemPath

	baseHeaderInfo[secretIDParam] = secretCode

	usersList := en.New()
	stRestful = libsecurityRestful.NewLibsecurityRestful()
	secureStorage, _ := ss.NewStorage([]byte(secretCode), true)
	stRestful.SetData(usersList, nil, nil, nil, secureStorage)
	stRestful.SetToFilterFlag(false)

	go runServer()
	time.Sleep(100 * time.Millisecond)
}

func runServer() {
	wsContainer := restful.NewContainer()
	s := NewSsRestful()
	s.SetData(stRestful)
	s.RegisterBasic(wsContainer)

	log.Printf("start listening on %v%v", host, port)
	server := &http.Server{Addr: port, Handler: wsContainer}
	log.Fatal(server.ListenAndServe())
}

func getExpectedData(sData string, okJ interface{}) (string, string, cr.Error, error) {
	found, exp, res, e, err := cr.GetExpectedData(sData, okJ)
	if found == true {
		return exp, res, e, err
	}

	switch okJ.(type) {
	case itemValue:
		var val itemValue
		err = json.Unmarshal([]byte(sData), &val)
		res = fmt.Sprintf("%v", val.Data)
		exp = fmt.Sprintf("%v", okJ.(itemValue).Data)
	case ss.SecureStorage:
		var data ss.SecureStorage
		err = json.Unmarshal([]byte(sData), &data)
		res = fmt.Sprintf("%v", data.Data)
		exp = fmt.Sprintf("%v", okJ.(ss.SecureStorage).Data)
	default:
		panic(fmt.Sprintf("Error unknown type: value: %v", okJ))
	}

	if err != nil {
		err = json.Unmarshal([]byte(sData), &e)
	}
	return exp, res, e, err
}

func HTTPDataMethodWithHeader(method string, url string, data string, headerInfo headerMapT) (int, string, error) {
	client := &http.Client{}
	request, err := http.NewRequest(method, url, strings.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	for key, value := range headerInfo {
		request.Header.Set(key, value)
	}
	request.AddCookie(&http.Cookie{Name: cr.AccessToken, Value: "", Path: "/"})
	response, err := client.Do(request)
	return cr.GetResponse(response, err)
}

func exeCommandCheckRes(t *testing.T, method string, url string, expCode int, data string, headerInfo headerMapT, okJ interface{}) string {
	code, sData, err := HTTPDataMethodWithHeader(method, url, data, headerInfo)
	logger.Trace.Println("Method:", method, "Url:", url, "data:", data, "header info:", headerInfo,
		"response code:", code, "response data:", sData, "error:", err)
	exp, res, e, err := getExpectedData(sData, okJ)
	if code != expCode || res != exp || err != nil {
		t.Errorf("Test fail: run %v '%v' Expected status: %v, received %v, expected data: '%v' received: '%v', error: %v %v",
			method, url, expCode, code, exp, res, e, err)
		t.FailNow()
	}
	return res
}

func initState(t *testing.T) {
}

// Test the following functions: add/get/delete item to/from storage and get storage
// 1. Create a storage, and 2 key-value to the storage
// 2. Get the items and verify their values
// 3. Get the storage information and compare to the expected data
// 4. Delete the items and verify that it is not in the storage
// 5. Remove storage and verify that the list is empty
func TestAddGetDeleteItem(t *testing.T) {
	keys := []string{"data1", "data2"}
	values := []string{"value1", "value2"}
	headerInfo := make(headerMapT)

	headerInfo[secretIDParam] = secretCode
	initState(t)
	okURLJ := cr.URL{URL: fmt.Sprintf("%v", servicePath)}
	for i, key := range keys {
		url := itemPath
		item, _ := json.Marshal(itemData{key, values[i]})
		exeCommandCheckRes(t, cr.HTTPPatchStr, url, http.StatusCreated, string(item), baseHeaderInfo, okURLJ)
		headerInfo[keyIDParam] = key
		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", headerInfo, itemValue{values[i]})
	}

	for i, key := range keys {
		url := itemPath
		headerInfo[keyIDParam] = key
		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusOK, "", headerInfo, itemValue{values[i]})
		exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", headerInfo, cr.EmptyStr)
		exeCommandCheckRes(t, cr.HTTPGetStr, url, http.StatusNotFound, "", headerInfo, cr.Error{Code: http.StatusNotFound})
	}

	url := fmt.Sprintf(cr.ConvertCommandToRequest(urlCommands[handleStorageCommand]), resourcePath)
	exeCommandCheckRes(t, cr.HTTPDeleteStr, url, http.StatusNoContent, "", baseHeaderInfo, cr.EmptyStr)
}
