package commonRestful

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
)

const (
	// HTTPGetStr : HTTP GET token
	HTTPGetStr = "GET"
	// HTTPPostStr : HTTP POST token
	HTTPPostStr = "POST"
	// HTTPPutStr : HTTP PUT token
	HTTPPutStr = "PUT"
	// HTTPDeleteStr : HTTP DELETE token
	HTTPDeleteStr = "DELETE"
	// HTTPPatchStr : HTTP PATCH token
	HTTPPatchStr = "PATCH"

	getMessageStr = "get-data"

	// SetCookieStr : token use to set the cookie
	SetCookieStr = "Set-Cookie"
	// AccessToken : token use to set the AccessToken
	AccessToken = "AccessToken"
	// NoMessageStr : define the empty message
	NoMessageStr = ""

	// VersionPath : define the version path
	VersionPath = "/version"
)

var (
	// ServicePathPrefix : prefix to be use by the RESTFul API
	ServicePathPrefix = "/forewind/app"
	// Version : the current RESTFul version
	Version = "/v1"

	// testCookieStr : for testing purposes
	testCookieStr string // = ""

	// EmptyStr : the defined EmptyStr
	EmptyStr = StringMessage{""}
)

// CommandToPath : hash map to convert between command and the relevant path
type CommandToPath map[int]string

// ComamndsToPath : Convert between command index and the relevant path
type ComamndsToPath struct {
	Command int
	Path    string
}

// Secret : secret struct definition
type Secret struct {
	Secret string
}

// UpdateSecret : UpdateSecret struct definition
type UpdateSecret struct {
	OldPassword string
	NewPassword string
}

// URL : Uel struct definition
type URL struct {
	URL string
}

// Match : Match struct definition for OK and when fail, include the message to pass
type Match struct {
	Match   bool
	Message string // in case of error
}

// Error : Error struct definition: the code and the relevant message
type Error struct {
	Code    int
	Message string
}

// StringMessage : StringMessage struct definition
type StringMessage struct {
	Str string
}

// FileData : the file path
type FileData struct {
	FilePath string
}

// SecureFile : SecureFile struct definition: file path and the associated secret
type SecureFile struct {
	FilePath string
	Secret   string
}

// ConvertCommandToRequest : Remove all the {} from the command string so it could be used for request
func ConvertCommandToRequest(cmd string) string {
	d := strings.Replace(cmd, "{", "", -1)
	return strings.Replace(d, "}", "", -1)
}

// GetResponse : parse the http response
func GetResponse(response *http.Response, err error) (int, string, error) {
	if err != nil {
		return -1, "", err
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return -1, "", err
	}
	return response.StatusCode, string(contents), nil
}

// HTTPDataMethod : extract the http data method and atach the cookie
func HTTPDataMethod(method string, url string, data string) (int, string, error) {
	client := &http.Client{}
	request, err := http.NewRequest(method, url, strings.NewReader(data))
	if err != nil {
		fmt.Println("Error in: HTTPDataMethod, error:", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: AccessToken, Value: testCookieStr, Path: "/"})
	response, err := client.Do(request)
	return GetResponse(response, err)
}

// RemoveSpaces : clean the given string from all white spaces, \r and \n
func RemoveSpaces(inStr string) string {
	d := strings.Replace(inStr, " ", "", -1)
	d = strings.Replace(d, "\n", "", -1)
	return strings.Replace(d, "\r", "", -1)
}

// GetExpectedData : check if the response data is as expected
func GetExpectedData(sData string, okJ interface{}) (bool, string, string, Error, error) {
	var e Error
	var err error
	errFound := false
	var res string
	var exp string

	switch okJ.(type) {
	case URL:
		var resURL URL
		json.Unmarshal([]byte(sData), &resURL)
		if len(resURL.URL) == 0 {
			errFound = true
		}
		res = resURL.URL
		exp = okJ.(URL).URL
	case []string:
		var per []string
		json.Unmarshal([]byte(sData), &per)
		sort.Strings(per)
		data := okJ.([]string)
		sort.Strings(data)
		for _, p := range data {
			exp += " " + p
		}
		for _, p := range per {
			res += " " + p
		}
	case Match:
		var matchOk Match
		json.Unmarshal([]byte(sData), &matchOk)
		if matchOk.Match == okJ.(Match).Match { // if it matched, ignore the message (error) in the comparison
			res = fmt.Sprintf("%v", matchOk.Match)
			exp = fmt.Sprintf("%v", okJ.(Match).Match)
		} else {
			res = fmt.Sprintf("%v", matchOk)
			exp = fmt.Sprintf("%v", okJ.(Match))
		}
	case StringMessage:
		res = sData
		exp = okJ.(StringMessage).Str
		if exp == getMessageStr { // get data to be used later
			exp = res
		}
	case Error:
		var errStr Error
		json.Unmarshal([]byte(sData), &errStr)
		if errStr.Code == 0 {
			errFound = true
		}
		res = fmt.Sprintf("%v", errStr.Code)
		exp = fmt.Sprintf("%v", okJ.(Error).Code)
	case FileData:
		var fileData FileData
		json.Unmarshal([]byte(sData), &fileData)
		if len(fileData.FilePath) == 0 {
			errFound = true
		}
		res = fmt.Sprintf("%v", fileData.FilePath)
		exp = fmt.Sprintf("%v", okJ.(FileData).FilePath)
	case SecureFile:
		var fileData SecureFile
		json.Unmarshal([]byte(sData), &fileData)
		if len(fileData.FilePath) == 0 {
			errFound = true
		}
		res = fmt.Sprintf("%v-%v", fileData.FilePath, fileData.Secret)
		exp = fmt.Sprintf("%v-%v", okJ.(SecureFile).FilePath, okJ.(SecureFile).Secret)
	default:
		return false, exp, res, e, err
	}

	if errFound == true {
		err = json.Unmarshal([]byte(sData), &e)
	}
	return true, exp, res, e, err
}

// TestSetCookie : set the cookie string to the given parameter
func TestSetCookie(cookieStr string) {
	testCookieStr = cookieStr
	logger.Trace.Println("Set cookie to:", testCookieStr)
}

// GetPropertyData : extract the property data from the relevant module
func GetPropertyData(userName string, propertyName string, usersList *en.EntityManager) (interface{}, error) {
	data, err := usersList.GetPropertyAttachedToEntity(userName, propertyName)
	if err != nil {
		return nil, err
	}
	return data, err
}
