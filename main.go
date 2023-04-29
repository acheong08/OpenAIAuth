package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/acheong08/OpenAIAuth/auth"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

func main() {
	username := os.Getenv("OPENAI_EMAIL")
	password := os.Getenv("OPENAI_PASSWORD")

	contentType := "application/x-www-form-urlencoded"
	userAgent := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"

	csrfUrl := "https://chat.openai.com/api/auth/csrf"
	promptLoginUrl := "https://chat.openai.com/api/auth/signin/auth0?prompt=login"
	loginUsernameUrl := "https://auth0.openai.com/u/login/identifier?state="
	loginPasswordUrl := "https://auth0.openai.com/u/login/password?state="
	authSessionUrl := "https://chat.openai.com/api/auth/session"

	getCsrfTokenErrorMessage := "Failed to get CSRF token."
	getAuthorizedUrlErrorMessage := "Failed to get authorized url."
	getStateErrorMessage := "Failed to get state."
	emailInvalidErrorMessage := "Email is not valid."
	emailOrPasswordInvalidErrorMessage := "Email or password is not correct."
	getAccessTokenErrorMessage := "Failed to get access token, please try again later."

	client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(tls_client.Chrome_110),
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
	}...)

	// get csrf token
	req, _ := http.NewRequest(http.MethodGet, csrfUrl, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || err != nil {
		log.Fatal(getCsrfTokenErrorMessage)
		return
	}

	data, _ := io.ReadAll(resp.Body)
	responseMap := make(map[string]string)
	json.Unmarshal(data, &responseMap)

	// get authorized url
	params := fmt.Sprintf(
		"callbackUrl=/&csrfToken=%s&json=true",
		responseMap["csrfToken"],
	)
	req, err = http.NewRequest(http.MethodPost, promptLoginUrl, strings.NewReader(params))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", userAgent)
	resp, err = client.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || err != nil {
		log.Fatal(getAuthorizedUrlErrorMessage)
		return
	}

	// get state
	data, _ = io.ReadAll(resp.Body)
	json.Unmarshal(data, &responseMap)
	req, err = http.NewRequest(http.MethodGet, responseMap["url"], nil)
	resp, err = client.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || err != nil {
		log.Fatal(getStateErrorMessage)
		return
	}

	// check username
	doc, _ := goquery.NewDocumentFromReader(resp.Body)
	state, _ := doc.Find("input[name=state]").Attr("value")
	params = fmt.Sprintf(
		"state=%s&username=%s&js-available=true&webauthn-available=true&is-brave=false&webauthn-platform-available=false&action=default",
		state,
		username,
	)
	req, err = http.NewRequest(http.MethodPost, loginUsernameUrl+state, strings.NewReader(params))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", userAgent)
	resp, err = client.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || err != nil {
		log.Fatal(emailInvalidErrorMessage)
		return
	}

	// check username and password
	params = fmt.Sprintf(
		"state=%s&username=%s&password=%s&action=default",
		state,
		username,
		password,
	)
	req, err = http.NewRequest(http.MethodPost, loginPasswordUrl+state, strings.NewReader(params))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", userAgent)
	resp, err = client.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || err != nil {
		log.Fatal(emailOrPasswordInvalidErrorMessage)
		return
	}

	// get access token
	req, err = http.NewRequest(http.MethodGet, authSessionUrl, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err = client.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || err != nil {
		log.Fatal(getAccessTokenErrorMessage)
		return
	}

	data, _ = io.ReadAll(resp.Body)
	fmt.Println(string(data))
}

func main_bak() {
	auth := auth.NewAuthenticator(os.Getenv("OPENAI_EMAIL"), os.Getenv("OPENAI_PASSWORD"), os.Getenv("PROXY"))
	err := auth.Begin()
	if err.Error != nil {
		println("Error: " + err.Details)
		println("Location: " + err.Location)
		println("Status code: " + fmt.Sprint(err.StatusCode))
		println("Embedded error: " + err.Error.Error())
		return
	}
	token, err := auth.GetAccessToken()
	if err.Error != nil {
		println("Error: " + err.Details)
		println("Location: " + err.Location)
		println("Status code: " + fmt.Sprint(err.StatusCode))
		println("Embedded error: " + err.Error.Error())
		return
	}
	fmt.Println(token)
}
