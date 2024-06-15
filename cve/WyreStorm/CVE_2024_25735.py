#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2024_25735:
    def get_url(self,input_url):
        try:
            url = input_url + "/device/config"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "softAP" in req.text:
                OutPrintInfoSuc("WyreStorm", f'目标存在CVE-2024-25735漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("WyreStorm", f"响应:\n{req.text.strip()}")
                else:
                    OutPrintInfoSuc("WyreStorm", f'目标存在CVE-2024-25735漏洞: {url}')
                    OutPutFile("wyrestorm_2024_25735.txt",f'目标存在CVE-2024-25735漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("WyreStorm", f'目标不存在CVE-2024-25735漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("WyreStorm",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WyreStorm", '开始检测CVE-2024-25735漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("WyreStorm", 'CVE-2024-25735漏洞检测结束')

