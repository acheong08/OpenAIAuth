package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"crypto/rand"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
)

type Error struct {
	Location   string
	StatusCode int
	Details    string
	Error      error
}

func NewError(location string, statusCode int, details string, err error) *Error {
	return &Error{
		Location:   location,
		StatusCode: statusCode,
		Details:    details,
		Error:      err,
	}
}

type Authenticator struct {
	EmailAddress       string
	Password           string
	Proxy              string
	Session            tls_client.HttpClient
	UserAgent          string
	State              string
	URL                string
	Verifier_code      string
	Verifier_challenge string
	AuthRequest        AuthRequest
	AuthResult         AuthResult
}

type AuthRequest struct {
	ClientID            string `json:"client_id"`
	Scope               string `json:"scope"`
	ResponseType        string `json:"response_type"`
	RedirectURL         string `json:"redirect_url"`
	Audience            string `json:"audience"`
	Prompt              string `json:"prompt"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type AuthResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	PUID         string `json:"puid"`
}

func NewAuthDetails(challenge string) AuthRequest {
	// Generate state (secrets.token_urlsafe(32))
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return AuthRequest{
		ClientID:            "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
		Scope:               "openid email profile offline_access model.request model.read organization.read",
		ResponseType:        "code",
		RedirectURL:         "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
		Audience:            "https://api.openai.com/v1",
		Prompt:              "login",
		State:               state,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
}

func NewAuthenticator(emailAddress, password, proxy string) *Authenticator {
	auth := &Authenticator{
		EmailAddress: emailAddress,
		Password:     password,
		Proxy:        proxy,
		UserAgent:    "ChatGPT/1.2023.187 (iOS 16.5.1; iPhone12,1; build 1744)",
	}
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(20),
		tls_client.WithClientProfile(tls_client.Safari_IOS_16_0),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar), // create cookieJar instance and pass it as argument
		// Proxy
		tls_client.WithProxyUrl(proxy),
	}
	auth.Session, _ = tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)

	// PKCE
	verifier, _ := pkce.CreateCodeVerifier()
	auth.Verifier_code = verifier.String()
	auth.Verifier_challenge = verifier.CodeChallengeS256()

	auth.AuthRequest = NewAuthDetails(auth.Verifier_challenge)

	return auth
}

func (auth *Authenticator) URLEncode(str string) string {
	return url.QueryEscape(str)
}

func (auth *Authenticator) Begin() *Error {
	// Just realized that the client id is hardcoded in the JS file

	return auth.partOne()
}

func (auth *Authenticator) preAuth() (string, *Error) {
	payload_i := map[string]interface{}{
		"bundle_id":    "com.openai.chat",
		"device_id":    "48E1EAA1-5D4D-4279-AA63-D42640CB4FB4",
		"request_flag": true,
		"device_token": "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",
	}

	payload_b, _ := json.Marshal(payload_i)

	headers := map[string]string{
		"Accept":          "application/json",
		"Content-Type":    "application/json",
		"User-Agent":      auth.UserAgent,
		"Host":            "ios.chat.openai.com",
		"OAI-Device-Id":   "48E1EAA1-5D4D-4279-AA63-D42640CB4FB4",
		"OAI-Client-Type": "ios",
	}

	req, _ := http.NewRequest("POST", "https://ios.chat.openai.com/backend-api/preauth_devicecheck", bytes.NewBuffer(payload_b))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return "", NewError("preauth_devicecheck", 0, "Failed to send request", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("preauth_devicecheck", resp.StatusCode, "Failed to send request", fmt.Errorf("error: Check details"))
	}
	var body map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return "", NewError("preauth_devicecheck", 0, "Failed to read body", err)
	}

	// Look for _preauth_devicecheck preauth_cookie in response set-preauth_cookie header
	preauth_cookie := ""
	for _, c := range resp.Cookies() {
		if c.Name == "_preauth_devicecheck" {
			preauth_cookie = c.Value
		}
	}

	if preauth_cookie == "" {
		return "", NewError("preauth_devicecheck", 0, "Failed to find preauth_cookie", fmt.Errorf("error: Check details"))
	}

	return preauth_cookie, nil

}

func (auth *Authenticator) partOne() *Error {

	auth_url := "https://auth0.openai.com/authorize"
	headers := map[string]string{
		"User-Agent":      auth.UserAgent,
		"Content-Type":    "application/x-www-form-urlencoded",
		"Accept":          "*/*",
		"Sec-Gpc":         "1",
		"Accept-Language": "en-US,en;q=0.8",
		"Origin":          "https://chat.openai.com",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Dest":  "empty",
		"Referer":         "https://chat.openai.com/auth/login",
		"Accept-Encoding": "gzip, deflate",
	}

	preauth_cookie, err1 := auth.preAuth()
	if err1 != nil {
		return err1
	}
	// Construct payload
	payload := url.Values{
		"client_id":             {auth.AuthRequest.ClientID},
		"scope":                 {auth.AuthRequest.Scope},
		"response_type":         {auth.AuthRequest.ResponseType},
		"redirect_uri":          {auth.AuthRequest.RedirectURL},
		"audience":              {auth.AuthRequest.Audience},
		"prompt":                {auth.AuthRequest.Prompt},
		"state":                 {auth.AuthRequest.State},
		"code_challenge":        {auth.AuthRequest.CodeChallenge},
		"code_challenge_method": {auth.AuthRequest.CodeChallengeMethod},
		"ios_app_version":       {"1744"},
		"ios_device_id":         {"48E1EAA1-5D4D-4279-AA63-D42640CB4FB4"},
		"preauth_cookie":        {preauth_cookie},
	}
	auth_url = auth_url + "?" + payload.Encode()
	req, _ := http.NewRequest("GET", auth_url, nil)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return NewError("part_one", 0, "Failed to send request", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewError("part_one", 0, "Failed to read body", err)
	}

	if resp.StatusCode == 302 {
		return auth.partTwo("https://auth0.openai.com" + resp.Header.Get("Location"))
	} else {
		return NewError("part_one", resp.StatusCode, string(body), fmt.Errorf("error: Check details"))
	}
}

func (auth *Authenticator) partTwo(url string) *Error {

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      auth.UserAgent,
		"Accept-Language": "en-US,en;q=0.9",
		"Referer":         "https://ios.chat.openai.com/",
	}

	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return NewError("part_two", 0, "Failed to make request", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 302 || resp.StatusCode == 200 {

		stateRegex := regexp.MustCompile(`state=(.*)`)
		stateMatch := stateRegex.FindStringSubmatch(string(body))
		if len(stateMatch) < 2 {
			return NewError("part_two", 0, "Could not find state in response", fmt.Errorf("error: Check details"))
		}

		state := strings.Split(stateMatch[1], `"`)[0]
		return auth.partThree(state)
	} else {
		return NewError("part_two", resp.StatusCode, string(body), fmt.Errorf("error: Check details"))

	}
}
func (auth *Authenticator) partThree(state string) *Error {

	url := fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", state)
	emailURLEncoded := auth.URLEncode(auth.EmailAddress)

	payload := fmt.Sprintf(
		"state=%s&username=%s&js-available=false&webauthn-available=true&is-brave=false&webauthn-platform-available=true&action=default",
		state, emailURLEncoded,
	)

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Origin":          "https://auth0.openai.com",
		"Connection":      "keep-alive",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"User-Agent":      auth.UserAgent,
		"Referer":         fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", state),
		"Accept-Language": "en-US,en;q=0.9",
		"Content-Type":    "application/x-www-form-urlencoded",
	}

	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return NewError("part_three", 0, "Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		return auth.partFour(state)
	} else {
		return NewError("part_three", resp.StatusCode, "Your email address is invalid.", fmt.Errorf("error: Check details"))

	}

}
func (auth *Authenticator) partFour(state string) *Error {

	url := fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", state)
	emailURLEncoded := auth.URLEncode(auth.EmailAddress)
	passwordURLEncoded := auth.URLEncode(auth.Password)
	payload := fmt.Sprintf("state=%s&username=%s&password=%s&action=default", state, emailURLEncoded, passwordURLEncoded)

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Origin":          "https://auth0.openai.com",
		"Connection":      "keep-alive",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"User-Agent":      auth.UserAgent,
		"Referer":         fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", state),
		"Accept-Language": "en-US,en;q=0.9",
		"Content-Type":    "application/x-www-form-urlencoded",
	}

	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return NewError("part_four", 0, "Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		redirectURL := resp.Header.Get("Location")
		return auth.partFive(state, redirectURL)
	} else {
		body := bytes.NewBuffer(nil)
		body.ReadFrom(resp.Body)
		return NewError("part_four", resp.StatusCode, body.String(), fmt.Errorf("error: Check details"))

	}

}
func (auth *Authenticator) partFive(oldState string, redirectURL string) *Error {

	url := "https://auth0.openai.com" + redirectURL

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      auth.UserAgent,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Referer":         fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", oldState),
	}

	req, _ := http.NewRequest("GET", url, nil)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return NewError("part_five", 0, "Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		auth.URL = resp.Header.Get("Location")
		return auth.partSix()
	} else {
		return NewError("part_five", resp.StatusCode, resp.Status, fmt.Errorf("error: Check details"))

	}

}
func (auth *Authenticator) partSix() *Error {
	code := regexp.MustCompile(`code=(.*)&`).FindStringSubmatch(auth.URL)
	if len(code) == 0 {
		return NewError("part_six", 0, auth.URL, fmt.Errorf("error: Check details"))
	}
	payload, _ := json.Marshal(map[string]string{
		"redirect_uri":  "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
		"grant_type":    "authorization_code",
		"client_id":     "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
		"code":          code[1],
		"code_verifier": auth.Verifier_code,
		"state":         auth.State,
	})

	req, _ := http.NewRequest("POST", "https://auth0.openai.com/oauth/token", strings.NewReader(string(payload)))
	for k, v := range map[string]string{
		"User-Agent":   auth.UserAgent,
		"content-type": "application/json",
	} {
		req.Header.Set(k, v)
	}
	resp, err := auth.Session.Do(req)
	if err != nil {
		return NewError("part_six", 0, "Failed to send request", err)
	}
	defer resp.Body.Close()
	// Parse response
	body, _ := io.ReadAll(resp.Body)
	// Parse as JSON
	var data map[string]interface{}

	err = json.Unmarshal(body, &data)

	if err != nil {
		return NewError("part_six", 0, "Response was not JSON", err)
	}

	// Check if access token in data
	if _, ok := data["access_token"]; !ok {
		return NewError("part_six", 0, "Missing access token", fmt.Errorf("error: Check details"))
	}
	auth.AuthResult.AccessToken = data["access_token"].(string)
	auth.AuthResult.RefreshToken = data["refresh_token"].(string)

	return nil
}

func (auth *Authenticator) GetAccessToken() string {
	return auth.AuthResult.AccessToken
}

func (auth *Authenticator) GetPUID() (string, *Error) {
	// Check if user has access token
	if auth.AuthResult.AccessToken == "" {
		return "", NewError("get_puid", 0, "Missing access token", fmt.Errorf("error: Check details"))
	}
	// Make request to https://chat.openai.com/backend-api/models
	req, _ := http.NewRequest("GET", "https://chat.openai.com/backend-api/models", nil)
	// Add headers
	req.Header.Add("Authorization", "Bearer "+auth.AuthResult.AccessToken)
	req.Header.Add("User-Agent", auth.UserAgent)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Referer", "https://chat.openai.com/")
	req.Header.Add("Origin", "https://chat.openai.com")
	req.Header.Add("Connection", "keep-alive")

	resp, err := auth.Session.Do(req)
	if err != nil {
		return "", NewError("get_puid", 0, "Failed to make request", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("get_puid", resp.StatusCode, "Failed to make request", fmt.Errorf("error: Check details"))
	}
	// Find `_puid` cookie in response
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "_puid" {
			auth.AuthResult.PUID = cookie.Value
			return cookie.Value, nil
		}
	}
	// If cookie not found, return error
	return "", NewError("get_puid", 0, "PUID cookie not found", fmt.Errorf("error: Check details"))
}

func (auth *Authenticator) GetAuthResult() AuthResult {
	return auth.AuthResult
}
