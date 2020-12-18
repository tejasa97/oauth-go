package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/tejasa97/utils-go/rest_errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8001",
		Timeout: 200 * time.Millisecond,
	}
)

type access_token struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
	Expires  int64  `json:"expires"`
}

func isPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return clientId
}

func AuthenticateRequest(request *http.Request) (*access_token, *rest_errors.RestErr) {
	if request == nil {
		return nil, nil
	}

	cleanRequest(request)

	// ex : api.bookstore.com/resource?access_token=xyz
	accessToken := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessToken == "" {
		return nil, rest_errors.NewBadRequestError("invalid access token provided")
	}

	at, err := getAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	request.Header.Add(headerXCallerId, fmt.Sprint("%v", at.UserID))
	request.Header.Add(headerXClientId, fmt.Sprint("%v", at.ClientID))

	return at, nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}
func getAccessToken(accessTokenId string) (*access_token, *rest_errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	// timeout or no response
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid rest client response when trying to login")
	}
	// error condition
	if response.StatusCode > 299 {
		var restErr rest_errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to login user")
		}
		return nil, &restErr
	}

	var accessToken access_token
	if err := json.Unmarshal(response.Bytes(), &accessToken); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token's response")
	}

	return &accessToken, nil
}
