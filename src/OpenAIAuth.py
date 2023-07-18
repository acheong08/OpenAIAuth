import time
import json
import undetected_chromedriver as uc
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC







class Auth0:

    def __init__(self, email: str, password: str, proxy: str = None, mfa: str = None):
        self.username = email#username
        self.password = password
        self.driver = None
        self.headless = True
        self.pageload_max = 10

        #mfa & proxy is ignored for now.


    def init_driver(self):
        if self.driver is None:
            self.driver = uc.Chrome(headless=self.headless)

    
    def get_access_token(self) -> str:
        #launch on demand
        self.init_driver()
        driver = self.driver

        # Navigate to the login page
        driver.get("https://chat.openai.com/auth/login")
        # Click the first button
        first_button = WebDriverWait(driver, self.pageload_max).until(
            EC.presence_of_element_located((By.XPATH, '/html/body/div[1]/div[1]/div[1]/div[4]/button[1]'))
        )
        first_button.click()

        # Enter the username
        username_field = WebDriverWait(driver, self.pageload_max).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="username"]'))
        )
        username_field.send_keys(self.username)

        # Click the second button
        second_button = WebDriverWait(driver, self.pageload_max).until(
            EC.presence_of_element_located((By.XPATH, '/html/body/div/main/section/div/div/div/div[1]/div/form/div[2]/button'))
        )
        second_button.click()

        # Enter the password
        password_field = WebDriverWait(driver, self.pageload_max).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="password"]'))
        )
        password_field.send_keys(self.password)

        # Click the third button
        third_button = WebDriverWait(driver, self.pageload_max).until(
            EC.presence_of_element_located((By.XPATH, '/html/body/div/main/section/div/div/div/form/div[3]/button'))
        )
        third_button.click()
       


        #load the whole page after login to get PUID
        #needs some adjusting..
        
        #/html/body/div[1]/div[1]/div[1]/div/div/div/nav/div[3]/div/svg    -> /html/body/div[1]/div[1]/div[1]/div/div/div/nav/div[3]/div
        try:
            WebDriverWait(driver, self.pageload_max).until(
                    EC.invisibility_of_element_located((By.XPATH, "/html/body/div[1]/div[1]/div[1]/div/div/div/nav/div[3]/div/svg")),
                    EC.presence_of_element_located((By.XPATH, "/html/body/div[1]/div[1]/div[1]/div/div/div/nav/div[3]/div/div/span[1]"))
            )
        except:
            print("timeout, either the site loaded very fast or theres a problem.")


        for cookie in self.driver.get_cookies():
            #print(cookie)
            if cookie["name"] == "_puid":
                self.puid = cookie["value"]



        #todo, we can get the session without loading this, just the chat.openai.com is enough
        driver.get("https://chat.openai.com/api/auth/session")
        pre_element = driver.find_element(By.TAG_NAME, 'pre')
        json_string = pre_element.text 



        json_obj = json.loads(json_string)

        access_token = json_obj.get('accessToken', None)
        self.access_token = access_token
        self.quit()
        return access_token


    def quit(self):
        if self.driver is not None:
            self.driver.quit()
            self.driver = None

    """
    //*[@id="radix-:rg:"]/div[2]/div[1]/div[2]/button
    //*[@id="radix-:rg:"]/div[2]/div[1]/div[2]/button[2]
    //*[@id="radix-:rg:"]/div[2]/div[1]/div[2]/button[2]
    """


    def get_puid(self) -> str:
        return self.puid or ""
        
    def __del__(self):
        self.quit()

