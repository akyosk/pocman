#! /usr/bin/python3
# -*- coding: utf-8 -*-
import requests
from libs.public.outprint import OutPrintInfo

import urllib3
urllib3.disable_warnings()
class JbossVulsScan:
    def _jboss_rce3(self, url):
        res_url = url + "/invoker/JMXInvokerServlet"
        try:
            response = requests.head(res_url, headers=self.header, verify=self.ssl, proxies=self.proxy,timeout=self.timeout)  # 发送HEAD请求获取响应头信息
            content_type = response.headers.get('content-type', '')
            if 'application/octet-stream' in content_type or 'application' in content_type:

                OutPrintInfo("JBoss",f"[b bright_red]存在Jboss-Rce,CVE-2015-7501 {res_url}")
                with open("./result/jbossVuls.txt", "a") as w:
                    w.write(f"存在CVE-2015-7501-RCE {res_url}\n")
        except Exception as e:
            pass

    def _jboss_rce(self, url):
        # print(url)
        try:
            res_url = f"{url}/invoker/readonly"
            # print(res_url)
            response = requests.get(url, headers=self.header, proxies=self.proxy, verify=self.ssl, timeout=self.timeout)
            if response.status_code == 500:
                OutPrintInfo("JBoss",f"[b bright_red]存在jboss-CVE-2017-12149-rce,网站位置{res_url}")
                with open("./result/jbossVuls.txt", "a") as w:
                    w.write(f"存在CVE-2017-12149-RCE {res_url}\n")
        except Exception as e:
            pass

    def _jboss_rce4(self, url):
        res_url = url + "/invoker/EJBInvokerServlet"
        try:
            response = requests.head(res_url, headers=self.header, verify=self.ssl, proxies=self.proxy,timeout=self.timeout)  # 发送HEAD请求获取响应头信息
            content_type = response.headers.get('content-type', '')
            if 'application/octet-stream' in content_type or 'application' in content_type:
                OutPrintInfo("JBoss",f"[b bright_red]存在Jboss-Rce,CVE-2013-4810,存在漏洞 {res_url}")
                with open("./result/jbossVuls.txt", "a") as w:
                    w.write(f"存在CVE-2013-4810-RCE {res_url}\n")
        except Exception as e:
            pass

    def _jboss_rce2(self, url):
        try:
            res_url = f"{url}/jbossmq-httpil/HTTPServerILServlet"
            response = requests.get(url, headers=self.header, proxies=self.proxy, verify=self.ssl, timeout=self.timeout)
            response.encoding = response.apparent_encoding
            if 'This is the JBossMQ HTTP-IL' in response.text:
                OutPrintInfo("JBoss",f"[b bright_red]存在jboss-CVE-2017-7504,网站位置 {res_url}")
                with open("./result/jbossVuls.txt", "a") as w:
                    w.write(f"存在CVE-2017-7504 {res_url}\n")
        except Exception as e:
            pass

    def main(self, results):
        url = results[0].strip('/ ')
        # OutPrintInfo("JBoss","开始检测Jboss-Rce......")
        self.ssl = results[1]
        header = results[2]
        proxy = results[3]
        self.timeout = int(results[4])
        self.proxy = {"http":proxy,"https":proxy}
        self.header = {"User-Agent":header}
        self._jboss_rce(url)
        self._jboss_rce2(url)
        self._jboss_rce3(url)
        self._jboss_rce4(url)
        # OutPrintInfo("JBoss","Jboss-Rce检测结束")

