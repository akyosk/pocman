#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()
class Cve_2023_24044:
    def main(self,target):
        OutPrintInfo("Plesk", '开始检测CVE-2023-24044重定向漏洞')
        url = target[0].strip('/ ')
        cdx = target[1]
        verify = target[2]
        header = target[3]
        proxy = target[4]
        reqset = ReqSet(proxy=proxy)
        proexis = reqset["proxy"]
        
        OutPrintInfo("Plesk", f'重定向网站: {cdx}')

        head = {
            'User-Agent': header,
            'Host': cdx,
        }

        response = requests.get(url, headers=head,verify=verify,proxies=proexis)
        if cdx in response.url:
            OutPrintInfo("Plesk", f'Url:[b bright_red]{url}[/b bright_red]存在CVE-2023-24044重定向漏洞')
            OutPrintInfo("Plesk", f'重定向网站:[b bright_red]{response.url}[/b bright_red]')
        else:
            OutPrintInfo("Plesk", f'目标 {url} 不存在漏洞')
        OutPrintInfo("Plesk", 'CVE-2023-24044重定向漏洞检测结束')