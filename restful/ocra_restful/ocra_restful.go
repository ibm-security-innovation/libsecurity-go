package ocra_restful

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	// en "ibm-security-innovation/libsecurity-go/entity"
	"github.com/emicklei/go-restful"
	stc "ibm-security-innovation/libsecurity-go/defs"
	logger "ibm-security-innovation/libsecurity-go/logger"
	"ibm-security-innovation/libsecurity-go/ocra"
	cr "ibm-security-innovation/libsecurity-go/restful/common_restful"
	"ibm-security-innovation/libsecurity-go/restful/libsecurity_restful"
)

const (
	OcraPrefix = "/ocra"

	usersPath = "/users"

	userIdParam                                 = "user-name"
	userNameComment                             = "user name"
	verifyUserIdentityChallengeToken            = "verify-oneway"
	verifyUserIdentityOtpToken                  = "verify-oneway-otp"
	keyToken                                    = "key"
	ocraSuiteToken                              = "ocraSuite"
	verifyUserIdentityMutualChallengeStep1Token = "verify-mutual-step1"
	verifyUserIdentityMutualChallengeStep2Token = "verify-mutual-step2"

	OcraQuestionLen = 8
)

var (
	ServicePath string // = cr.ServicePathPrefix + OcraPrefix
)

type ocraRestful struct {
	st *libsecurity_restful.LibsecurityRestful
}

type OcraUserData struct {
	Secret    string
	OcraSuite string
}

type OcraData struct {
	ServerQuestion string
	ClientQuestion string
	Counter        string
	Password       string
	SessionId      string
	TimeStamp      string
	Otp            string
}

func init() {
	initCommandToPath()
}

func NewOcraRestful() *ocraRestful {
	return &ocraRestful{}
}

func (o *ocraRestful) SetData(stR *libsecurity_restful.LibsecurityRestful) {
	o.st = stR
}

func (o ocraRestful) getUrlPath(request *restful.Request, name string) cr.Url {
	return cr.Url{Url: fmt.Sprintf("%v/%v", ServicePath, name)}
}

func (o ocraRestful) setError(response *restful.Response, httpStatusCode int, err error) {
	data, _ := json.Marshal(cr.Error{Code: httpStatusCode, Message: fmt.Sprintf("%v", err)})
	response.WriteErrorString(httpStatusCode, string(data))
}

func (o ocraRestful) getOcra(request *restful.Request, response *restful.Response) *ocra.UserOcra {
	userName := request.PathParameter(userIdParam)
	data, err := cr.GetPropertyData(userName, stc.OcraPropertyName, o.st.UsersList)
	if err != nil {
		o.setError(response, http.StatusNotFound, err)
		return nil
	}
	return data.(*ocra.UserOcra)
}

func (o ocraRestful) restAddOcra(request *restful.Request, response *restful.Response) {
	var OcraData OcraUserData
	name := request.PathParameter(userIdParam)

	err := request.ReadEntity(&OcraData)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
		return
	}
	data, err := ocra.NewOcraUser([]byte(OcraData.Secret), OcraData.OcraSuite)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
		return
	}
	err = o.st.UsersList.AddPropertyToEntity(name, stc.OcraPropertyName, data)
	if err != nil {
		l.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(o.getUrlPath(request, name))
}

func (o ocraRestful) restUpdateOcraKey(request *restful.Request, response *restful.Response) {
	var secret cr.Secret

	name := request.PathParameter(userIdParam)
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
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(o.getUrlPath(request, name))
}

func (o ocraRestful) restUpdateOcraSuite(request *restful.Request, response *restful.Response) {
	var ocraSuite cr.StringMessage

	name := request.PathParameter(userIdParam)
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
	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(o.getUrlPath(request, name))
}

func (o ocraRestful) restGetOcra(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	response.WriteEntity(data)
	response.WriteHeader(http.StatusOK)
}

func (o ocraRestful) restDeleteOcra(request *restful.Request, response *restful.Response) {
	name := request.PathParameter(userIdParam)
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	err := o.st.UsersList.RemovePropertyFromEntity(name, stc.OcraPropertyName)
	if err != nil {
		o.setError(response, http.StatusBadRequest, err)
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}

func (o ocraRestful) getRandString(length int) string {
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

func (o ocraRestful) restVerifyOcraUserIdentityChallenge(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	serverFirstData := OcraData{ServerQuestion: o.getRandString(OcraQuestionLen)}
	response.WriteHeader(http.StatusOK)
	response.WriteEntity(serverFirstData)
}

func (o ocraRestful) restVerifyOcraUserIdentityCheckOtp(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	var OcraData OcraData
	err := request.ReadEntity(&OcraData)
	if err != nil {
		str := fmt.Sprintf("Error while reading data '%v', error: %v", OcraData, err)
		o.setError(response, http.StatusNotFound, fmt.Errorf(str))
		return
	}
	// verify client OTP
	otp, err := ocra.GenerateOCRAAdvance(data.OcraSuite, string(data.Key), OcraData.Counter,
		OcraData.ServerQuestion, OcraData.Password, OcraData.SessionId, OcraData.TimeStamp)
	response.WriteHeader(http.StatusOK)
	logger.Trace.Println("OcraData:", OcraData, "otp:", otp, "client otp:", OcraData.Otp)
	if OcraData.Otp == otp && err == nil {
		response.WriteEntity(cr.Match{Match: true, Message: "OTP match"})
		logger.Trace.Println("Server verify the OTP successfully")
	} else {
		logger.Trace.Println("Server calculated OTP:", otp, "is different from the one sent from the client", OcraData.Otp)
		response.WriteEntity(cr.Match{Match: false, Message: "OTP doesn't match"})
	}
}

func (o ocraRestful) restVerifyOcraUserIdentityMutualChallengeStep1(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	var OcraData OcraData
	err := request.ReadEntity(&OcraData)
	logger.Trace.Println("Server received data:", OcraData, "Error:", err)
	OcraData.ServerQuestion = o.getRandString(OcraQuestionLen)
	serverOtp, err := ocra.GenerateOCRAAdvance(data.OcraSuite, string(data.Key),
		OcraData.Counter, OcraData.ClientQuestion+OcraData.ServerQuestion, OcraData.Password, OcraData.SessionId, OcraData.TimeStamp)
	if err != nil {
		o.setError(response, http.StatusNotFound, err)
		return
	}
	response.WriteHeader(http.StatusOK)
	logger.Trace.Println("OcraData:", OcraData, "server otp:", serverOtp)
	OcraData.Otp = serverOtp
	response.WriteEntity(OcraData)
}

func (o ocraRestful) restVerifyOcraUserIdentityMutualChallengeStep2(request *restful.Request, response *restful.Response) {
	data := o.getOcra(request, response)
	if data == nil {
		return
	}
	var OcraData OcraData
	err := request.ReadEntity(&OcraData)
	clientOtp, err := ocra.GenerateOCRAAdvance(data.OcraSuite, string(data.Key),
		OcraData.Counter, OcraData.ServerQuestion+OcraData.ClientQuestion, OcraData.Password, OcraData.SessionId, OcraData.TimeStamp)
	response.WriteHeader(http.StatusOK)
	logger.Trace.Println("OcraData:", OcraData, "client otp:", OcraData.Otp, "calculated client otp:", clientOtp)
	if OcraData.Otp == clientOtp && err == nil {
		response.WriteEntity(cr.Match{Match: true, Message: "OTP match"})
		logger.Trace.Println("Server verify the OTP successfully")
	} else {
		logger.Trace.Println("Server calculated OTP:", clientOtp, "is different from the one sent from the client", OcraData.Otp)
		response.WriteEntity(cr.Match{Match: false, Message: "Client OTP doesn't match"})
	}
}
