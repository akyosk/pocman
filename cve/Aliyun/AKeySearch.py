#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class AKeySearchVuls:
    def __init__(self):
        self.proexis = None
        self.headers = None

    def run(self,url):
        try:
            response = requests.get(url, headers=self.headers, verify=self.verify, proxies=self.proexis,timeout=self.timeout)
            if "accessKey" in response.text and "LTAI" in response.text:
                OutPrintInfoSuc("ALiYUN", f"Found Key Url:{url}")
                if self.batch:
                    OutPutFile("aliyun_key_info.txt",f"Found Key Url:{url}")
                
            else:
                if not self.batch:
                    OutPrintInfo("ALiYUN", f"目标不存在AliYun-Key泄漏")

        except Exception as e:
            if not self.batch:
                OutPrintInfo("ALiYUN", f"目标请求出错")


    def main(self, results):
        self.batch = results["batch_work"]
        url = results["url"].strip('/ ')
        header = results["header"]
        proxy = results["proxy"]
        self.verify = results["ssl"]
        self.timeout = int(results["timeout"])
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("ALiYUN", "开始检测AliYun-Key泄漏...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("ALiYUN", "AliYun-Key泄漏检测结束")
