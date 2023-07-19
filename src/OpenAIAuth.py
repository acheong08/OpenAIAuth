# Credits to github.com/rawandahmad698/PyChatGPT
import re
import os
import urllib

import tls_client as requests


class Error(Exception):
    """
    Base error class
    """

    location: str
    status_code: int
    details: str

    def __init__(self, location: str, status_code: int, details: str):
        self.location = location
        self.status_code = status_code
        self.details = details


class Auth0:
    """
    OpenAI Authentication Reverse Engineered
    """

    def __init__(
        self,
        email_address: str,
        password: str,
        puid: str = None,
        proxy: str = None,
    ):
        puid = puid or os.environ.get("PUID")
        # if not puid:
        #     raise ValueError("PUID is required")
        self.email_address = email_address
        self.password = password
        self.proxy = proxy
        self.session = requests.Session(
            client_identifier="chrome112",
            random_tls_extension_order=True,
        )
        proxies = {
            "http": self.proxy,
            "https": self.proxy,
        }
        self.session.proxies.update(proxies)
        self.access_token: str = None
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
        self.session.cookies.set("_puid", puid)

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
        In part two, We make a request to https://chat.openai.com/api/auth/csrf and grab a fresh csrf token
        """
        url = "https://chat.openai.com/api/auth/csrf"
        headers = {
            "Host": "chat.openai.com",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": "https://chat.openai.com/auth/login",
            "Accept-Encoding": "gzip, deflate, br",
        }
        response = self.session.get(
            url=url,
            headers=headers,
        )
        if response.status_code == 200 and "json" in response.headers["Content-Type"]:
            csrf_token = response.json()["csrfToken"]
            # self.session.cookies.set("__Host-next-auth.csrf-token", csrf_token)
            self.__part_one(token=csrf_token)
        else:
            error = Error(
                location="begin",
                status_code=response.status_code,
                details=response.text,
            )
            print(error.details)
            raise error

    def __part_one(self, token: str) -> None:
        """
        We reuse the token from part to make a request to /api/auth/signin/auth0?prompt=login
        """
        url = "https://chat.openai.com/api/auth/signin/auth0?prompt=login"
        payload = f"callbackUrl=%2F&csrfToken={token}&json=true"
        headers = {
            "Host": "chat.openai.com",
            "User-Agent": self.user_agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Sec-Gpc": "1",
            "Accept-Language": "en-US,en;q=0.8",
            "Origin": "https://chat.openai.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://chat.openai.com/auth/login",
            "Accept-Encoding": "gzip, deflate",
            #
        }
        response = self.session.post(url=url, headers=headers, data=payload)
        if response.status_code == 200 and "json" in response.headers["Content-Type"]:
            url = response.json()["url"]
            if (
                url == "https://chat.openai.com/api/auth/error?error=OAuthSignin"
                or "error" in url
            ):
                error = Error(
                    location="__part_one",
                    status_code=response.status_code,
                    details="You have been rate limited. Please try again later.",
                )
                raise error
            self.__part_two(url=url)
        else:
            error = Error(
                location="__part_one",
                status_code=response.status_code,
                details=response.text,
            )
            raise error

    def __part_two(self, url: str) -> None:
        """
        We make a GET request to url
        :param url:
        :return:
        """
        headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://chat.openai.com/",
        }
        response = self.session.get(
            url=url,
            headers=headers,
        )
        if response.status_code == 302 or response.status_code == 200:
            state = re.findall(r"state=(.*)", response.text)[0]
            state = state.split('"')[0]
            self.__part_three(state=state)
        else:
            error = Error(
                location="__part_two",
                status_code=response.status_code,
                details=response.text,
            )
            raise error

    def __part_three(self, state: str) -> None:
        """
        We use the state to get the login page
        """
        url = f"https://auth0.openai.com/u/login/identifier?state={state}"

        headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://chat.openai.com/",
        }
        response = self.session.get(url, headers=headers)
        if response.status_code == 200:
            self.__part_four(state=state)
        else:
            error = Error(
                location="__part_three",
                status_code=response.status_code,
                details=response.text,
            )
            raise error

    def __part_four(self, state: str) -> None:
        """
        We make a POST request to the login page with the captcha, email
        :param state:
        :return:
        """
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
        if response.status_code == 302 or response.status_code == 200:
            self.__part_five(state=state)
        else:
            error = Error(
                location="__part_four",
                status_code=response.status_code,
                details="Your email address is invalid.",
            )
            raise error

    def __part_five(self, state: str) -> None:
        """
        We enter the password
        :param state:
        :return:
        """

        email_url_encoded = self.url_encode(self.email_address)
        password_url_encoded = self.url_encode(self.password)
        payload = f"state={state}&username={email_url_encoded}&password={password_url_encoded}&action=default"
        url = f"https://auth0.openai.com/u/login/password?state={state}"
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
        response = self.session.post(
            url,
            headers=headers,
            allow_redirects=False,
            data=payload,
        )
        if response.status_code == 302:
            redirect_url = response.headers.get("Location")
            self.__part_six(old_state=state, redirect_url=redirect_url)
        else:
            error = Error(
                location="__part_five",
                status_code=response.status_code,
                details="Your credentials are invalid.",
            )
            raise error

    def __part_six(self, old_state: str, redirect_url) -> None:
        url = "https://auth0.openai.com" + redirect_url
        headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": f"https://auth0.openai.com/u/login/password?state={old_state}",
        }
        response = self.session.get(url, headers=headers, allow_redirects=False)
        if response.status_code == 302:
            redirect_url = response.headers.get("Location")
            self.__part_seven(redirect_url=redirect_url, previous_url=url)
        else:
            error = Error(
                location="__part_six",
                status_code=response.status_code,
                details=response.text,
            )
            raise error

    def __part_seven(self, redirect_url: str, previous_url: str) -> None:
        url = redirect_url
        headers = {
            "Host": "chat.openai.com",
            "Accept": "application/json",
            "Connection": "keep-alive",
            "User-Agent": self.user_agent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": previous_url,
        }
        response = self.session.get(url, headers=headers, allow_redirects=True)
        if response.status_code == 200:
            return
        else:
            error = Error(
                location="__part_seven",
                status_code=response.status_code,
                details=response.text,
            )
            raise error

    def get_access_token(self):
        """
        Gets access token
        """
        self.begin()
        response = self.session.get(
            "https://chat.openai.com/api/auth/session",
        )
        if response.status_code == 200:
            self.access_token = response.json().get("accessToken")
            return self.access_token
        else:
            error = Error(
                location="get_access_token",
                status_code=response.status_code,
                details=response.text,
            )
            raise error

    def get_puid(self) -> str:
        url = os.getenv("OPENAI_MODELS_URL", "https://bypass.churchless.tech/models")
        headers = {
            "Authorization": "Bearer " + self.access_token,
        }
        resp = self.session.get(url, headers=headers)
        if resp.status_code == 200:
            # Get _puid cookie
            puid = resp.headers.get("Set-Cookie", "")
            if not puid:
                raise Exception("Get _puid cookie failed.")
            self.puid = puid.split("_puid=")[1].split(";")[0]
            return self.puid
        else:
            raise Exception(resp.text)


if __name__ == "__main__":
    import os

    email = os.getenv("OPENAI_EMAIL")
    password = os.getenv("OPENAI_PASSWORD")
    openai = Auth0(email, password)
    print(openai.get_access_token())

    print(openai.get_puid())
