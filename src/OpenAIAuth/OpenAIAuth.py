# Credits to github.com/rawandahmad698/PyChatGPT
import re
import urllib

import tls_client


class Debugger:
    def __init__(self, debug: bool = False):
        if debug:
            print("Debugger enabled on OpenAIAuth")
        self.debug = debug

    def set_debug(self, debug: bool):
        self.debug = debug

    def log(self, message: str, end: str = "\n"):
        if self.debug:
            print(message, end=end)


class OpenAIAuth:
    def __init__(
        self,
        email_address: str,
        password: str,
        proxy: str = None,
        debug: bool = False,
    ):
        self.session_token = None
        self.email_address = email_address
        self.password = password
        self.proxy = proxy
        self.session = tls_client.Session(
            client_identifier="chrome_109",
        )
        self.access_token: str = None
        self.debugger = Debugger(debug)
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"

    @staticmethod
    def url_encode(string: str) -> str:
        """
        URL encode a string
        :param string:
        :return:
        """
        return urllib.parse.quote(string)

    def begin(self) -> None:
        """
        Begin the auth process
        """
        self.debugger.log("Beginning auth process")
        if not self.email_address or not self.password:
            return

        if self.proxy:
            proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }
            self.session.proxies = proxies

        # First, make a request to https://explorer.api.openai.com/auth/login
        url = "https://explorer.api.openai.com/"
        headers = {
            "Host": "ask.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        response = self.session.get(
            url=url,
            headers=headers,
        )
        if response.status_code == 200:
            self.__part_two()
        else:
            self.debugger.log("Error in part one")
            self.debugger.log("Response: ", end="")
            self.debugger.log(response.text)
            self.debugger.log("Status code: ", end="")
            self.debugger.log(response.status_code)
            raise Exception("API error")

    def __part_two(self) -> None:
        """
        In part two, We make a request to https://explorer.api.openai.com/api/auth/csrf and grab a fresh csrf token
        """
        self.debugger.log("Beginning part two")

        url = "https://explorer.api.openai.com/api/auth/csrf"
        headers = {
            "Host": "ask.openai.com",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": "https://explorer.api.openai.com/auth/login",
            "Accept-Encoding": "gzip, deflate, br",
        }
        response = self.session.get(
            url=url,
            headers=headers,
        )
        if response.status_code == 200 and "json" in response.headers["Content-Type"]:
            csrf_token = response.json()["csrfToken"]
            self.__part_three(token=csrf_token)
        else:
            self.debugger.log("Error in part two")
            self.debugger.log("Response: ", end="")
            self.debugger.log(response.text)
            self.debugger.log("Status code: ", end="")
            self.debugger.log(response.status_code)
            raise Exception("Error logging in")

    def __part_three(self, token: str) -> None:
        """
        We reuse the token from part to make a request to /api/auth/signin/auth0?prompt=login
        """
        self.debugger.log("Beginning part three")
        url = "https://explorer.api.openai.com/api/auth/signin/auth0?prompt=login"
        payload = f"callbackUrl=%2F&csrfToken={token}&json=true"
        headers = {
            "Host": "explorer.api.openai.com",
            "User-Agent": self.user_agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Sec-Gpc": "1",
            "Accept-Language": "en-US,en;q=0.8",
            "Origin": "https://explorer.api.openai.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://explorer.api.openai.com/auth/login",
            "Accept-Encoding": "gzip, deflate",
        }
        self.debugger.log("Payload: " + payload)
        self.debugger.log("Payload length: " + str(len(payload)))
        response = self.session.post(url=url, headers=headers, data=payload)
        if response.status_code == 200 and "json" in response.headers["Content-Type"]:
            url = response.json()["url"]
            if (
                url
                == "https://explorer.api.openai.com/api/auth/error?error=OAuthSignin"
                or "error" in url
            ):
                self.debugger.log("You have been rate limited")
                raise Exception("You have been rate limited.")
            self.__part_four(url=url)
        else:
            self.debugger.log("Error in part three")
            self.debugger.log("Response: ", end="")
            self.debugger.log("Status code: ", end="")
            self.debugger.log(response.status_code)
            self.debugger.log(response.headers)
            self.debugger.log(self.session.cookies.get_dict())
            raise Exception("Unknown error")

    def __part_four(self, url: str) -> None:
        """
        We make a GET request to url
        :param url:
        :return:
        """
        self.debugger.log("Beginning part four")
        headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://explorer.api.openai.com/",
        }
        response = self.session.get(
            url=url,
            headers=headers,
        )
        if response.status_code == 302:
            try:
                state = re.findall(r"state=(.*)", response.text)[0]
                state = state.split('"')[0]
                self.__part_five(state=state)
            except IndexError as exc:
                self.debugger.log("Error in part four")
                self.debugger.log("Status code: ", end="")
                self.debugger.log(response.status_code)
                self.debugger.log("Rate limit hit")
                self.debugger.log("Response: " + str(response.text))
                raise Exception("Rate limit hit") from exc
        else:
            self.debugger.log("Error in part four")
            self.debugger.log("Response: ", end="")
            self.debugger.log(response.text)
            self.debugger.log("Status code: ", end="")
            self.debugger.log(response.status_code)
            self.debugger.log("Wrong response code")
            raise Exception("Unknown error")

    def __part_five(self, state: str) -> None:
        """
        We use the state to get the login page & check for a captcha
        """
        self.debugger.log("Beginning part five")
        url = f"https://auth0.openai.com/u/login/identifier?state={state}"

        headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://explorer.api.openai.com/",
        }
        response = self.session.get(url, headers=headers)
        if response.status_code == 200:
            self.__part_six(state=state)
        else:
            self.debugger.log("Error in part five")
            self.debugger.log("Response: ", end="")
            self.debugger.log(response.text)
            self.debugger.log("Status code: ", end="")
            self.debugger.log(response.status_code)
            raise ValueError("Invalid response code")

    def __part_six(self, state: str) -> None:
        """
        We make a POST request to the login page with the captcha, email
        :param state:
        :return:
        """
        self.debugger.log("Beginning part six")
        url = f"https://auth0.openai.com/u/login/identifier?state={state}"
        email_url_encoded = self.url_encode(self.email_address)

        payload = (
            f"state={state}&username={email_url_encoded}&js-available=false&webauthn-available=true&is"
            f"-brave=false&webauthn-platform-available=true&action=default "
        )

        headers = {
            "Host": "auth0.openai.com",
            "Origin": "https://auth0.openai.com",
            "Connection": "keep-alive",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": self.user_agent,
            "Referer": f"https://auth0.openai.com/u/login/identifier?state={state}",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        response = self.session.post(
            url,
            headers=headers,
            data=payload,
        )
        if response.status_code == 302:
            self.__part_seven(state=state)
        else:
            self.debugger.log("Error in part six")
            self.debugger.log("Response: ", end="")
            self.debugger.log(response.text)
            self.debugger.log("Status code: ", end="")
            self.debugger.log(response.status_code)
            raise Exception("Unknown error")

    def __part_seven(self, state: str) -> None:
        """
        We enter the password
        :param state:
        :return:
        """
        url = f"https://auth0.openai.com/u/login/password?state={state}"
        self.debugger.log("Beginning part seven")
        email_url_encoded = self.url_encode(self.email_address)
        password_url_encoded = self.url_encode(self.password)
        payload = f"state={state}&username={email_url_encoded}&password={password_url_encoded}&action=default"
        headers = {
            "Host": "auth0.openai.com",
            "Origin": "https://auth0.openai.com",
            "Connection": "keep-alive",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": self.user_agent,
            "Referer": f"https://auth0.openai.com/u/login/password?state={state}",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            response = self.session.post(
                url,
                headers=headers,
                data=payload,
            )
            self.debugger.log("Request went through")
        except Exception as exc:
            self.debugger.log("Error in part seven")
            self.debugger.log("Exception: ", end="")
            self.debugger.log(exc)
            raise Exception("Could not get response") from exc
        if response.status_code == 302:
            self.debugger.log("Response code is 302")
            try:
                new_state = re.findall(r"state=(.*)", response.text)[0]
                new_state = new_state.split('"')[0]
                self.debugger.log("New state found")
                self.__part_eight(old_state=state, new_state=new_state)
            except Exception as exc:
                raise Exception("Could not find new state") from exc
        else:
            self.debugger.log("Error in part seven")
            self.debugger.log("Status code: ", end="")
            self.debugger.log(response.status_code)
            raise Exception("Wrong status code")

    def __part_eight(self, old_state: str, new_state) -> None:
        self.debugger.log("Beginning part eight")
        url = f"https://auth0.openai.com/authorize/resume?state={new_state}"
        headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": f"https://auth0.openai.com/u/login/password?state={old_state}",
        }
        response = self.session.get(
            url,
            headers=headers,
            allow_redirects=True,
        )
        if response.status_code == 200:
            self.session_token = response.cookies.get_dict()[
                "__Secure-next-auth.session-token"
            ]
            self.get_access_token()

    def get_access_token(self):
        """
        Gets access token
        """
        self.session.cookies.set(
            "__Secure-next-auth.session-token",
            self.session_token,
        )
        response = self.session.get(
            "https://explorer.api.openai.com/api/auth/session",
        )
        if response.status_code == 200:
            self.access_token = response.json()["accessToken"]
            self.debugger.log("Access token found")
            return self.access_token
        else:
            self.debugger.log("Error in part nine")
            self.debugger.log("Status code: ", end="")
            self.debugger.log(response.status_code)
            raise Exception("Wrong status code")
