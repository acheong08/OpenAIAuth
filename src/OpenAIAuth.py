# -*- coding: utf-8 -*-
# By @pengzhile on GitHub

import datetime
import re
from datetime import datetime as dt
from os import getenv
from urllib.parse import urlparse, parse_qs
import requests
from certifi import where
import uuid
import json


class Auth0:
    def __init__(
        self,
        email: str,
        password: str,
        proxy: str = None,
        mfa: str = None,
    ):
        """
        Initializes an instance of the Auth0 class.

        Args:
        - email (str): The email address of the user.
        - password (str): The password of the user.
        - proxy (str, optional): The proxy server to use for requests. Defaults to None.
        - mfa (str, optional): The multi-factor authentication method. Defaults to None.
        """
        self.session_token = None
        self.email = email
        self.password = password
        self.mfa = mfa
        self.session = requests.Session()
        self.req_kwargs = {
            "proxies": {
                "http": proxy,
                "https": proxy,
            }
            if proxy
            else None,
            "verify": where(),
            "timeout": 100,
        }
        self.access_token = None
        self.expires = None
        self.user_agent = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/109.0.0.0 Safari/537.36"
        )

    @staticmethod
    def __check_email(email: str):
        regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
        return re.fullmatch(regex, email)

    def get_access_token(self) -> str:
        """
        Authenticates the user and returns the access token.

        Returns:
        - str: The access token.
        """

        if not self.__check_email(self.email) or not self.password:
            raise Exception("invalid email or password.")

        return self.__part_one()

    def __part_one(self):
        url = "https://ios.chat.openai.com/backend-api/preauth_devicecheck"
        headers = {
           "User-Agent": "ChatGPT/1.2023.187 (iOS 16.5.1; iPad1 4,3; build 1744)",
            "Content-Type": "application/json"
        }
        

        payload = {
            "bundle_id": "com.openai.chat",
            "device_id": str(uuid.uuid4()),
            "request_flag": True,
            "device_token": getenv("IOS_DEVICE_TOKEN", "")
        }

        resp = requests.post(url, headers=headers, data=json.dumps(payload))

        if resp.status_code == 200:
            preauth = resp.cookies.get("_preauth_devicecheck")
            if preauth is None:
                raise Exception('Failed to get preauth cookie. Please check your device token.')

            return self.__part_two(preauth)
        else:
            raise Exception('Request error when trying to get preauth cookie')


    def __part_two(self, preauth: str) -> str:
        code_challenge = "w6n3Ix420Xhhu-Q5-mOOEyuPZmAsJHUbBpO8Ub7xBCY"
        code_verifier = "yGrXROHx_VazA0uovsxKfE263LMFcrSrdm4SlC-rob8"

        url = (
            "https://auth0.openai.com/authorize?client_id=pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh&audience=https%3A%2F"
            "%2Fapi.openai.com%2Fv1&redirect_uri=com.openai.chat%3A%2F%2Fauth0.openai.com%2Fios%2Fcom.openai.chat"
            "%2Fcallback&scope=openid%20email%20profile%20offline_access%20model.request%20model.read"
            "%20organization.read%20offline&response_type=code&code_challenge={}"
            "&code_challenge_method=S256&prompt=login&preauth_cookie={}".format(code_challenge, preauth)
        )
        return self.__part_three(code_verifier, url)

    def __part_three(self, code_verifier, url: str) -> str:
        headers = {
            "User-Agent": self.user_agent,
            "Referer": "https://ios.chat.openai.com/",
        }
        resp = self.session.get(
            url, headers=headers, allow_redirects=True, **self.req_kwargs
        )

        if resp.status_code == 200:
            try:
                url_params = parse_qs(urlparse(resp.url).query)
                state = url_params["state"][0]
                return self.__part_four(code_verifier, state)
            except IndexError as exc:
                raise Exception("Rate limit hit.") from exc
        else:
            raise Exception("Error request login url.")

    def __part_four(self, code_verifier: str, state: str) -> str:
        url = "https://auth0.openai.com/u/login/identifier?state=" + state
        headers = {
            "User-Agent": self.user_agent,
            "Referer": url,
            "Origin": "https://auth0.openai.com",
        }
        data = {
            "state": state,
            "username": self.email,
            "js-available": "true",
            "webauthn-available": "true",
            "is-brave": "false",
            "webauthn-platform-available": "false",
            "action": "default",
        }
        resp = self.session.post(
            url, headers=headers, data=data, allow_redirects=False, **self.req_kwargs
        )

        if resp.status_code == 302:
            return self.__part_five(code_verifier, state)
        else:
            raise Exception("Error check email.")

    def __part_five(self, code_verifier: str, state: str) -> str:
        url = "https://auth0.openai.com/u/login/password?state=" + state
        headers = {
            "User-Agent": self.user_agent,
            "Referer": url,
            "Origin": "https://auth0.openai.com",
        }
        data = {
            "state": state,
            "username": self.email,
            "password": self.password,
            "action": "default",
        }

        resp = self.session.post(
            url, headers=headers, data=data, allow_redirects=False, **self.req_kwargs
        )
        if resp.status_code == 302:
            location = resp.headers["Location"]
            if not location.startswith("/authorize/resume?"):
                raise Exception("Login failed.")

            return self.__part_six(code_verifier, location, url)

        if resp.status_code == 400:
            raise Exception("Wrong email or password.")
        else:
            raise Exception("Error login.")

    def __part_six(self, code_verifier: str, location: str, ref: str) -> str:
        url = "https://auth0.openai.com" + location
        headers = {
            "User-Agent": self.user_agent,
            "Referer": ref,
        }

        resp = self.session.get(
            url, headers=headers, allow_redirects=False, **self.req_kwargs
        )
        if resp.status_code == 302:
            location = resp.headers["Location"]
            if location.startswith("/u/mfa-otp-challenge?"):
                if not self.mfa:
                    raise Exception("MFA required.")
                return self.__part_seven(code_verifier, location)

            if not location.startswith(
                "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback?"
            ):
                raise Exception("Login callback failed.")

            return self.__get_access_token(code_verifier, resp.headers["Location"])

        raise Exception("Error login.")

    def __part_seven(self, code_verifier: str, location: str) -> str:
        url = "https://auth0.openai.com" + location
        data = {
            "state": parse_qs(urlparse(url).query)["state"][0],
            "code": self.mfa,
            "action": "default",
        }
        headers = {
            "User-Agent": self.user_agent,
            "Referer": url,
            "Origin": "https://auth0.openai.com",
        }

        resp = self.session.post(
            url, headers=headers, data=data, allow_redirects=False, **self.req_kwargs
        )
        if resp.status_code == 302:
            location = resp.headers["Location"]
            if not location.startswith("/authorize/resume?"):
                raise Exception("MFA failed.")

            return self.__part_six(code_verifier, location, url)

        if resp.status_code == 400:
            raise Exception("Wrong MFA code.")
        else:
            raise Exception("Error login.")

    def __get_access_token(self, code_verifier: str, callback_url: str) -> str:
        url_params = parse_qs(urlparse(callback_url).query)

        if "error" in url_params:
            error = url_params["error"][0]
            error_description = (
                url_params["error_description"][0]
                if "error_description" in url_params
                else ""
            )
            raise Exception("{}: {}".format(error, error_description))

        if "code" not in url_params:
            raise Exception("Error get code from callback url.")

        url = "https://auth0.openai.com/oauth/token"
        headers = {
            "User-Agent": self.user_agent,
        }
        data = {
            "redirect_uri": "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
            "grant_type": "authorization_code",
            "client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
            "code": url_params["code"][0],
            "code_verifier": code_verifier,
        }
        resp = self.session.post(
            url, headers=headers, json=data, allow_redirects=False, **self.req_kwargs
        )

        if resp.status_code == 200:
            json = resp.json()
            if "access_token" not in json:
                raise Exception("Get access token failed, maybe you need a proxy.")

            self.access_token = json["access_token"]
            self.expires = (
                dt.utcnow()
                + datetime.timedelta(seconds=json["expires_in"])
                - datetime.timedelta(minutes=5)
            )
            return self.access_token
        else:
            raise Exception(resp.text)

    def get_puid(self) -> str:
        url = getenv("OPENAI_MODELS_URL", "https://bypass.churchless.tech/models")
        headers = {
            "Authorization": "Bearer " + self.access_token,
        }
        resp = self.session.get(url, headers=headers, **self.req_kwargs)
        if resp.status_code == 200:
            # Get _puid cookie
            puid = resp.headers.get("set-cookie", "")
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
