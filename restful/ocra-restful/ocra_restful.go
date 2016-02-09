package ocraRestful

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/emicklei/go-restful"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	"github.com/ibm-security-innovation/libsecurity-go/ocra"
	cr "github.com/ibm-security-innovation/libsecurity-go/restful/common-restful"
	"github.com/ibm-security-innovation/libsecurity-go/restful/libsecurity-restful"
)

const (
	ocraPrefix = "/ocra"

	usersPath = "/users"

	userIDParam                                 = "user-name"
	userNameComment                             = "user name"
	verifyUserIdentityChallengeToken            = "verify-oneway"
	verifyUserIdentityOtpToken                  = "verify-oneway-otp"
	keyToken                                    = "key"
	ocraSuiteToken                              = "ocraSuite"
	verifyUserIdentityMutualChallengeStep1Token = "verify-mutual-step1"
	verifyUserIdentityMutualChallengeStep2Token = "verify-mutual-step2"

	ocraQuestionLen = 8
)

var (
	servicePath string // = cr.ServicePathPrefix + ocraPrefix
)

// OcraRestful : OCRA restful structure
type OcraRestful struct {
	st *libsecurityRestful.LibsecurityRestful
}

type ocraUserData struct {
	Secret    string
	OcraSuite string
}

type ocraData struct {
	ServerQuestion string
	ClientQuestion string
	Counter        string
	Password       string
	SessionID      string
	TimeStamp      string
	Otp            string
}

func init() {
	initCommandToPath()
}

// NewOcraRestful : return a pointer to the NewOcraRestful structure
func NewOcraRestful() *OcraRestful {
	return &OcraRestful{}
}

// SetData : initialize the OcraRestful structure
func (o *OcraRestful) SetData(stR *libsecurityRestful.LibsecurityRestful) {
	o.st = stR
}

func (o OcraRestful) getURLPath(request *restful.Request, name string) cr.URL {
	return cr.URL{URL: fmt.Sprintf("%v/%v", servicePath, name)}
}

func (o OcraRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (o OcraRestful) getOcra(request *restful.Request, response *restful.Response) *ocra.UserOcra {
	userName := request.PathParameter(userIDParam)
	data, err := cr.GetPropertyData(userName, defs.OcraPropertyName, o.st.UsersList)
	if err != nil {
		o.setError(response, http.StatusNotFound, err)
		return nil
	}
	return data.(*ocra.UserOcra)
}

func (o OcraRestful) restAddOcra(request *restful.Request, response *restful.Response) {
	var ocraData ocraUserData
	name := request.PathParameter(userIDParam)

	err := request.ReadEntity(&ocraData)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
		return
	}
	data, err := ocra.NewOcraUser([]byte(ocraData.Secret), ocraData.OcraSuite)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
		return
	}
	err = o.st.UsersList.AddPropertyToEntity(name, defs.OcraPropertyName, data)
	if err != nil {
		o.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeaderAndEntity(http.StatusCreated, o.getURLPath(request, name))
}

func (o OcraRestful) restUpdateOcraKey(request *restful.Request, response *restful.Response) {
	var secret cr.Secret

	name := request.PathParameter(userIDParam)
	err := request.ReadEntity(&secret)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
		return
	}
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	err = data.UpdateOcraKey([]byte(secret.Secret))
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeaderAndEntity(http.StatusCreated, o.getURLPath(request, name))
}

func (o OcraRestful) restUpdateOcraSuite(request *restful.Request, response *restful.Response) {
	var ocraSuite cr.StringMessage

	name := request.PathParameter(userIDParam)
	err := request.ReadEntity(&ocraSuite)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
		return
	}
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	err = data.UpdateOcraSuite(ocraSuite.Str)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
		return
	}
	response.WriteHeaderAndEntity(http.StatusCreated, o.getURLPath(request, name))
}

func (o OcraRestful) restGetOcra(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	response.WriteHeaderAndEntity(http.StatusOK, data)
}

func (o OcraRestful) restDeleteOcra(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIDParam)
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	err := o.st.UsersList.RemovePropertyFromEntity(name, defs.OcraPropertyName)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (o OcraRestful) getRandString(length int) string {
	secret := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, secret)
	if err != nil {
		panic(fmt.Errorf("random read failed: %v", err))
	}

	for i := 0; i < length; i++ {
		if secret[i] < 'a' || secret[i] > 'z' {
			secret[i] = (secret[i] % ('z' - 'a')) + 'a'
		}
	}
	return string(secret)
}

func (o OcraRestful) restVerifyOcraUserIdentityChallenge(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	serverFirstData := ocraData{ServerQuestion: o.getRandString(ocraQuestionLen)}
	response.WriteHeaderAndEntity(http.StatusOK, serverFirstData)
}

func (o OcraRestful) restVerifyOcraUserIdentityCheckOtp(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	var ocraData ocraData
	err := request.ReadEntity(&ocraData)
	if err != nil {
		str := fmt.Sprintf("Error while reading data '%v', error: %v", ocraData, err)
		o.setError(response, http.StatusNotFound, fmt.Errorf(str))
		return
	}
	// verify client OTP
	otp, err := ocra.GenerateOCRAAdvance(data.OcraSuite, string(data.Key), ocraData.Counter,
		ocraData.ServerQuestion, ocraData.Password, ocraData.SessionID, ocraData.TimeStamp)
	logger.Trace.Println("ocraData:", ocraData, "otp:", otp, "client otp:", ocraData.Otp)
	if ocraData.Otp == otp && err == nil {
		response.WriteHeaderAndEntity(http.StatusOK, cr.Match{Match: true, Message: "OTP match"})
		logger.Trace.Println("Server verify the OTP successfully")
	} else {
		logger.Trace.Println("Server calculated OTP:", otp, "is different from the one sent from the client", ocraData.Otp)
		response.WriteHeaderAndEntity(http.StatusOK, cr.Match{Match: false, Message: "OTP doesn't match"})
	}
}

func (o OcraRestful) restVerifyOcraUserIdentityMutualChallengeStep1(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	var ocraData ocraData
	err := request.ReadEntity(&ocraData)
	logger.Trace.Println("Server received data:", ocraData, "Error:", err)
	ocraData.ServerQuestion = o.getRandString(ocraQuestionLen)
	serverOtp, err := ocra.GenerateOCRAAdvance(data.OcraSuite, string(data.Key),
		ocraData.Counter, ocraData.ClientQuestion+ocraData.ServerQuestion, ocraData.Password, ocraData.SessionID, ocraData.TimeStamp)
	if err != nil {
		o.setError(response, http.StatusNotFound, err)
		return
	}
	logger.Trace.Println("ocraData:", ocraData, "server otp:", serverOtp)
	ocraData.Otp = serverOtp
	response.WriteHeaderAndEntity(http.StatusOK, ocraData)
}

func (o OcraRestful) restVerifyOcraUserIdentityMutualChallengeStep2(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	var ocraData ocraData
	err := request.ReadEntity(&ocraData)
	clientOtp, err := ocra.GenerateOCRAAdvance(data.OcraSuite, string(data.Key),
		ocraData.Counter, ocraData.ServerQuestion+ocraData.ClientQuestion, ocraData.Password, ocraData.SessionID, ocraData.TimeStamp)
	logger.Trace.Println("ocraData:", ocraData, "client otp:", ocraData.Otp, "calculated client otp:", clientOtp)
	if ocraData.Otp == clientOtp && err == nil {
		response.WriteHeaderAndEntity(http.StatusOK, cr.Match{Match: true, Message: "OTP match"})
		logger.Trace.Println("Server verify the OTP successfully")
	} else {
		logger.Trace.Println("Server calculated OTP:", clientOtp, "is different from the one sent from the client", ocraData.Otp)
		response.WriteHeaderAndEntity(http.StatusOK, cr.Match{Match: false, Message: "Client OTP doesn't match"})
	}
}
