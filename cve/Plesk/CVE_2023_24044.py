#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2023_24044:
    def main(self,target):
        self.batch = target["batch_work"]
        if not self.batch:
            OutPrintInfo("Plesk", '开始检测CVE-2023-24044重定向漏洞')
        url = target["url"].strip('/ ')
        cdx = target["cdx"]
        verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            reqset = ReqSet(proxy=proxy)
            proexis = reqset["proxy"]
        else:
            proexis = {"http": proxy, "https": proxy}
        if not self.batch:
            OutPrintInfo("Plesk", f'重定向网站: {cdx}')

        head = {
            'User-Agent': header,
            'Host': cdx,
        }

        response = requests.get(url, headers=head,verify=verify,proxies=proexis)
        if cdx in response.url:
            OutPrintInfoSuc("Plesk", f'Url:{url}存在CVE-2023-24044重定向漏洞')
            if not self.batch:

                OutPrintInfo("Plesk", f'重定向网站:{response.url}')
            else:
                OutPutFile("plesk_2023_24044.txt", f'目标存在CVE-2023-24044重定向漏洞: {url}')
        else:
            if not self.batch:
                OutPrintInfo("Plesk", f'目标 {url} 不存在漏洞')
        if not self.batch:
            OutPrintInfo("Plesk", 'CVE-2023-24044重定向漏洞检测结束')