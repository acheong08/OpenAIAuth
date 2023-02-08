"""
Gets cf_clearance details
"""
import re
from time import sleep

import undetected_chromedriver as uc


class Cloudflare:
    """
    Gets cloudflare clearance via browser automation.
    """

    def __init__(
        self,
        proxy: str = None,
        driver_exec_path: str = None,
        browser_exec_path: str = None,
    ) -> None:
        self.proxy: str = proxy
        self.cf_clearance: str = None
        self.user_agent: str = None
        self.driver_exec_path: str = driver_exec_path
        self.browser_exec_path: str = browser_exec_path
        self.cf_cookie_found: bool = False
        self.agent_found: bool = False

    def __get_chrome_options(self):
        options = uc.ChromeOptions()
        options.add_argument("--start_maximized")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-application-cache")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-setuid-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        if self.proxy:
            options.add_argument("--proxy-server=" + self.proxy)
        return options

    def __detect_cookies(self, message):
        if "params" in message:
            if "headers" in message["params"]:
                if "set-cookie" in message["params"]["headers"]:
                    # Use regex to get the cookie for cf_clearance=*;
                    cf_clearance_cookie = re.search(
                        "cf_clearance=.*?;",
                        message["params"]["headers"]["set-cookie"],
                    )
                    if cf_clearance_cookie and not self.cf_cookie_found:
                        print("Found Cloudflare Cookie!")
                        # remove the semicolon and 'cf_clearance=' from the string
                        raw_cf_cookie = cf_clearance_cookie.group(0)
                        self.cf_clearance = raw_cf_cookie.split("=")[1][:-1]
                        self.cf_cookie_found = True

    def __detect_user_agent(self, message):
        if "params" in message:
            if "headers" in message["params"]:
                if "user-agent" in message["params"]["headers"]:
                    # Use regex to get the cookie for cf_clearance=*;
                    user_agent = message["params"]["headers"]["user-agent"]
                    self.user_agent = user_agent
                    self.agent_found = True

    def get_cf_cookies(self) -> tuple:
        """
        Get cloudflare cookies.

        :return: None
        """
        driver = None
        try:
            self.cf_cookie_found = False
            self.agent_found = False
            self.cf_clearance = None
            self.user_agent = None
            options = self.__get_chrome_options()
            print("Spawning browser...")
            driver = uc.Chrome(
                enable_cdp_events=True,
                options=options,
                driver_executable_path=self.driver_exec_path,
                browser_executable_path=self.browser_exec_path,
            )
            print("Browser spawned.")
            driver.add_cdp_listener(
                "Network.responseReceivedExtraInfo",
                lambda msg: self.__detect_cookies(msg),
            )
            driver.add_cdp_listener(
                "Network.requestWillBeSentExtraInfo",
                lambda msg: self.__detect_user_agent(msg),
            )
            driver.get("https://chat.openai.com/chat")
            while not self.agent_found or not self.cf_cookie_found:
                sleep(5)
        finally:
            # Close the browser
            if driver is not None:
                driver.quit()
                del driver
        return self.cf_clearance, self.user_agent
