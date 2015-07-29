package common_restful

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	en "ibm-security-innovation/libsecurity-go/entity"
	logger "ibm-security-innovation/libsecurity-go/logger"
)

const (
	GET_STR    = "GET"
	POST_STR   = "POST"
	PUT_STR    = "PUT"
	DELETE_STR = "DELETE"
	PATCH_STR  = "PATCH"

	GetMessageStr = "get-data"

	SetCookieStr = "Set-Cookie"
	AccessToken  = "AccessToken"
	NoMessageStr = ""

	VersionPath = "/version"
)

var (
	ServicePathPrefix = "/forewind/app"
	Version           = "/v1"

	CookieStr string = ""

	EmptyStr = StringMessage{""}
)

type CommandToPath map[int]string

type ComamndsToPath struct {
	Command int
	Path    string
}

type Secret struct {
	Secret string
}

type UpdateSecret struct {
	OldPassword string
	NewPassword string
}

type Url struct {
	Url string
}

type Match struct {
	Match   bool
	Message string // in case of error
}

type Error struct {
	Code    int
	Message string
}

type StringMessage struct {
	Str string
}

type FileData struct {
	FilePath string
}

type SecureFile struct {
	FilePath string
	Secret   string
}

// Remove all the {} from the command string so it could be used for request
func ConvertCommandToRequest(cmd string) string {
	d := strings.Replace(cmd, "{", "", -1)
	return strings.Replace(d, "}", "", -1)
}

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

func HttpDataMethod(method string, url string, data string) (int, string, error) {
	client := &http.Client{}
	request, err := http.NewRequest(method, url, strings.NewReader(data))
	if err != nil {
		fmt.Println("Error in: HttpDataMethod, error:", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: AccessToken, Value: CookieStr, Path: "/"})
	response, err := client.Do(request)
	return GetResponse(response, err)
}

func RemoveSpaces(inStr string) string {
	d := strings.Replace(inStr, " ", "", -1)
	d = strings.Replace(d, "\n", "", -1)
	return strings.Replace(d, "\r", "", -1)
}

func GetExpectedData(sData string, okJ interface{}) (bool, string, string, Error, error) {
	var e Error
	var err error = nil
	errFound := false
	var res string
	var exp string

	switch okJ.(type) {
	case Url:
		var resUrl Url
		json.Unmarshal([]byte(sData), &resUrl)
		if len(resUrl.Url) == 0 {
			errFound = true
		}
		res = resUrl.Url
		exp = okJ.(Url).Url
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
		if exp == GetMessageStr { // get data to be used later
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

func SetCookie(cookieStr string) {
	CookieStr = cookieStr
	logger.Trace.Println("Set cookie to:", CookieStr)
}

func GetPropertyData(userName string, propertyName string, usersList *en.EntityManager) (interface{}, error) {
	data, err := usersList.GetPropertyAttachedToEntity(userName, propertyName)
	if err != nil {
		return nil, err
	}
	return data, err
}
