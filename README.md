# OpenAIAuth
Library/Tool for automated authentication to ChatGPT. Intended for use with a tool like cURL to automate interactions with the OpenAI web interface.

The cURL tool is often used in command-line contexts to make HTTP requests. Unlike a web browser or a browser automation tool like Puppeteer or Selenium, cURL doesn't automatically handle CSRF authentication. Thus, if a web application uses CSRF tokens as part of its security, browserless automated interactions with the application must correctly handle these tokens. This involves extracting the CSRF token from a set-cookie HTTP header, storing it, and then including it in subsequent requests as required by the application.

A CSRF token, or Cross-Site Request Forgery token, is a security measure used in web development to protect against CSRF attacks. In a CSRF attack, an attacker tricks a victim into performing an action on a web application in which they're authenticated. This is possible because web applications often trust that actions coming from a user's browser are intentional and legitimate when the user is authenticated. A CSRF token is a way to prevent these attacks. It's a unique, random value associated with a user's session, and it's typically embedded within the web form that the user is submitting. When the form is submitted, the server checks that the token in the form matches the token associated with the user's session. If the tokens don't match, the request is rejected. This obviously poses an obstacle to browserless automation.

Note that the more accepted way to automate browserless interactions with OpenAI is via their API, with an API access token. For most use cases, that would be better. Possible reasons to automate via cURL, instead, include making automated requests through one's $20/month ChatGPT Plus subscription (as opposed to the pay-as-you-go API rate) and to make use of plugins or other browser-exclusive functionality that is not available through the API.

## Overview of the Code
The entry point is the `main` function in the `main` module: 

1. It creates a new instance of the `Authenticator` from the `auth` package using the `NewAuthenticator` function. This function requires three environment variables: `OPENAI_EMAIL`, `OPENAI_PASSWORD`, and `PROXY`.

2. The `Authenticator` then initiates the authentication process with the Begin method. If this method encounters an error, it prints out the details and exits the program.

3. If the `Begin` method is successful, the program then calls the `GetAccessToken` method on the `Authenticator` to retrieve an access token. If this process encounters an error, it prints out the details and exits the program. If successful, it prints the retrieved access token.

In the `OpenAiAuth.go` file, we have the `Authenticator` struct which carries out several operations to authenticate the user with the OpenAI service:

1. The `Begin` method sends a `GET` request to the OpenAI service to retrieve a CSRF token.

2. If successful, it calls the `partOne` method, passing the CSRF token. This method sends a POST request to the OpenAI service with the CSRF token as part of the payload.

3. The `partOne` method then calls the `partTwo` method if the previous operation was successful. This method sends a `GET` request to another OpenAI service URL and captures a state variable from the response.

4. The `partTwo` method then calls `partThree` which sends another `GET` request, this time to auth0.openai.com.

3. The `partThree` method calls `partFour` if the previous operation was successful. This method sends a `POST` request to the OpenAI service, providing the user's email address and the previously retrieved state.

4. The `partFour` method calls `partFive` if the previous operation was successful. This method sends another `POST` request to the OpenAI service, this time providing both the user's email and password along with the state.

5. Finally, the `partFive` method calls `partSix` if the previous operation was successful. This method sends a `GET` request to the OpenAI service with the `redirectURL` received from the response of `partFive`.

The end result of this sequence of operations is to authenticate the user with the OpenAI service and retrieve an access token, which can be used for subsequent requests to the service. Note that the choice of the user-agent string in the `Authenticator` struct emulates a Chrome browser on Linux.

## Credits
- @linweiyuan
- @rawandahmad698
- @pengzhile
