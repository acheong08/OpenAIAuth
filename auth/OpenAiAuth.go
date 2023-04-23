package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
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
	EmailAddress string
	Password     string
	Proxy        string
	Session      tls_client.HttpClient
	AccessToken  string
	UserAgent    string
	State        string
	URL          string
}

func NewAuthenticator(emailAddress, password, proxy string) *Authenticator {
	auth := &Authenticator{
		EmailAddress: emailAddress,
		Password:     password,
		Proxy:        proxy,
		UserAgent:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	}
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(20),
		tls_client.WithClientProfile(tls_client.Chrome_110),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar), // create cookieJar instance and pass it as argument
		// Proxy
		tls_client.WithProxyUrl(proxy),
	}
	auth.Session, _ = tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	return auth
}

func (auth *Authenticator) URLEncode(str string) string {
	return url.QueryEscape(str)
}

func (auth *Authenticator) Begin() Error {

	return auth.partOne()
}
func (auth *Authenticator) partOne() Error {

	url := "https://ai.fakeopen.com/auth/endpoint"
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

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return *NewError("part_one", 0, "", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return *NewError("part_one", 0, "", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return *NewError("part_one", 0, "", err)
	}

	if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "json") {

		var urlResponse struct {
			URL   string `json:"url"`
			State string `json:"state"`
		}
		err = json.Unmarshal(body, &urlResponse)
		if err != nil {
			return *NewError("part_one", 0, "", err)
		}

		auth.State = urlResponse.State

		url := urlResponse.URL
		if url == "https://chat.openai.com/api/auth/error?error=OAuthSignin" || strings.Contains(url, "error") {
			err := NewError("part_one", resp.StatusCode, "You have been rate limited. Please try again later.", fmt.Errorf("error: Check details"))
			return *err
		}

		return auth.partTwo(url)
	} else {
		err := NewError("part_one", resp.StatusCode, string(body), fmt.Errorf("error: Check details"))
		return *err
	}
}

func (auth *Authenticator) partTwo(url string) Error {

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      auth.UserAgent,
		"Accept-Language": "en-US,en;q=0.9",
		"Referer":         "https://chat.openai.com/",
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return *NewError("part_two", 0, "", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return *NewError("part_two", 0, "", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return *NewError("part_two", 0, "", err)
	}

	if resp.StatusCode == 302 || resp.StatusCode == 200 {

		stateRegex := regexp.MustCompile(`state=(.*)`)
		stateMatch := stateRegex.FindStringSubmatch(string(body))
		if len(stateMatch) < 2 {
			return *NewError("part_two", 0, "Could not find state in response", fmt.Errorf("error: Check details"))
		}

		state := strings.Split(stateMatch[1], `"`)[0]
		return auth.partThree(state)
	} else {
		err := NewError("__part_two", resp.StatusCode, string(body), fmt.Errorf("error: Check details"))
		return *err
	}
}

func (auth *Authenticator) partThree(state string) Error {

	url := fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", state)

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      auth.UserAgent,
		"Accept-Language": "en-US,en;q=0.9",
		"Referer":         "https://chat.openai.com/",
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return *NewError("part_three", 0, "", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return *NewError("part_three", 0, "", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return *NewError("part_three", 0, "", err)
	}

	if resp.StatusCode == 200 {
		return auth.partFour(state)
	} else {
		err := NewError("__part_three", resp.StatusCode, string(body), fmt.Errorf("error: Check details"))
		return *err
	}

}
func (auth *Authenticator) partFour(state string) Error {

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

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return *NewError("part_four", 0, "", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return *NewError("part_four", 0, "", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		return auth.partFive(state)
	} else {
		err := NewError("__part_four", resp.StatusCode, "Your email address is invalid.", fmt.Errorf("error: Check details"))
		return *err
	}

}
func (auth *Authenticator) partFive(state string) Error {

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

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return *NewError("part_five", 0, "", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return *NewError("part_five", 0, "", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		redirectURL := resp.Header.Get("Location")
		return auth.partSix(state, redirectURL)
	} else {
		body := bytes.NewBuffer(nil)
		_, err1 := body.ReadFrom(resp.Body)
		if err1 != nil {
			return *NewError("part_five", 0, "", err1)
		}
		err := NewError("__part_five", resp.StatusCode, body.String(), fmt.Errorf("error: Check details"))
		return *err
	}

}
func (auth *Authenticator) partSix(oldState string, redirectURL string) Error {

	url := "https://auth0.openai.com" + redirectURL

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      auth.UserAgent,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Referer":         fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", oldState),
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return *NewError("part_six", 0, "", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := auth.Session.Do(req)
	if err != nil {
		return *NewError("part_six", 0, "", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		auth.URL = resp.Header.Get("Location")
		return Error{}
	} else {
		err := NewError("__part_six", resp.StatusCode, resp.Status, fmt.Errorf("error: Check details"))
		return *err
	}

}
func (auth *Authenticator) GetAccessToken() (string, Error) {
	url := "https://ai.fakeopen.com/auth/token"

	payload := fmt.Sprintf("state=%s&callbackUrl=%s", auth.State, auth.URLEncode(auth.URL))

	println(payload)

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return "", *NewError("get_access_token", 0, "", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := auth.Session.Do(req)
	if err != nil {
		return "", *NewError("get_access_token", 0, "", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", *NewError("get_access_token", 0, "", err)
		}
		if result["accessToken"] == nil {
			return "", *NewError("get_access_token", 0, "", fmt.Errorf("error: accessToken is nil"))
		}

		auth.AccessToken = result["accessToken"].(string)
		return auth.AccessToken, Error{}
	} else {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", *NewError("get_access_token", 0, "", err)
		}
		return "", *NewError("get_access_token", resp.StatusCode, string(body), fmt.Errorf("error: Check details"))
	}
}
