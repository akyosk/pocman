#! /usr/bin/python3
# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class JbossVulsScan:
    def _jboss_wsq(self, urls):
        url = urls + '/jmx-console'
        try:
            response = requests.get(url=url, headers=self.header, verify=self.ssl, timeout=3, proxies=self.proxy)
            if response.status_code == 200 and '404' not in response.text:
                OutPrintInfoSuc("JBoss", f"存在jboss未授权,默认密码[b bright_red]admin/admin[/b bright_red]{url}")
                if self.batch:
                    OutPutFile("jboss_vuls.txt",f"存在jboss未授权,默认密码admin/admin{url}")


            else:
                if not self.batch:
                    OutPrintInfo("JBoss", "目标不存在jboss未授权")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("JBoss", "目标请求出错")

    def _jboss_rce3(self, url):
        res_url = url + "/invoker/JMXInvokerServlet"
        try:
            response = requests.head(res_url, headers=self.header, verify=self.ssl, proxies=self.proxy)  # 发送HEAD请求获取响应头信息
            content_type = response.headers.get('content-type', '')
            if 'application/octet-stream' in content_type or 'application' in content_type:
                OutPrintInfoSuc("JBoss",f"存在Jboss-Rce,cve-2015-7501,若访问网站下载文件则存在漏洞{res_url}")
                if self.batch:
                    OutPutFile("jboss_vuls.txt",f"存在CVE-2015-7501,若访问网站下载文件则存在漏洞{res_url}")
            else:
                if not self.batch:
                    OutPrintInfo("JBoss", "目标不存在CVE-2015-7501")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("JBoss", "目标请求出错")

    def _jboss_rce(self, url):
        try:
            res_url = f"{url}/invoker/readonly"
            response = requests.get(url, headers=self.header, proxies=self.proxy, verify=self.ssl, timeout=5)
            if response.status_code == 500:
                if not self.batch:
                    OutPrintInfoSuc("JBoss",f"响应码为500存在jboss-CVE-2017-12149-rce,工具https://github.com/yunxu1/jboss-_CVE-2017-12149，网站位置 {res_url}")
                else:
                    OutPrintInfoSuc("JBoss",
                                    f"响应码为500存在CVE-2017-12149 {res_url}")
                    OutPutFile("jboss_vuls.txt", f"存在Jboss-Rce,cve-2017-12149漏洞{res_url}")
            else:
                if not self.batch:
                    OutPrintInfo("JBoss", "目标不存在CVE-2017-12149")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("JBoss", "目标请求出错")

    def _jboss_rce4(self, url):
        res_url = url + "/invoker/EJBInvokerServlet"
        try:
            response = requests.head(res_url, headers=self.header, verify=self.ssl, proxies=self.proxy)  # 发送HEAD请求获取响应头信息
            content_type = response.headers.get('content-type', '')
            if 'application/octet-stream' in content_type or 'application' in content_type:
                OutPrintInfoSuc("JBoss",f"存在CVE-2013-4810,若访问网站下载文件则存在漏洞 {res_url}")
                if self.batch:
                    OutPutFile("jboss_vuls.txt", f"存在Jboss-Rce,cve-2013-4810漏洞{res_url}")
            else:
                if not self.batch:
                    OutPrintInfo("JBoss", "目标不存在CVE-2013-4810")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("JBoss", "目标请求出错")

    def _jboss_rce2(self, url):
        try:
            res_url = f"{url}/jbossmq-httpil/HTTPServerILServlet"
            response = requests.get(url, headers=self.header, proxies=self.proxy, verify=self.ssl, timeout=5)
            response.encoding = response.apparent_encoding
            if 'This is the JBossMQ HTTP-IL' in response.text:
                if not self.batch:
                    OutPrintInfoSuc("JBoss",f"存在jboss-CVE-2017-7504,工具https://github.com/joaomatosf/JavaDeserH2HC，网站位置 {res_url}")
                else:
                    OutPrintInfoSuc("JBoss",
                                 f"存在jboss-CVE-2017-7504 {res_url}")
                    OutPutFile("jboss_vuls.txt", f"存在存在jboss-CVE-2017-7504漏洞{res_url}")
            else:
                if not self.batch:
                    OutPrintInfo("JBoss", "目标不存在CVE-2017-7504")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("JBoss", "目标请求出错")

    def main(self, results):
        self.batch = results["batch_work"]
        url = results["url"].strip('/ ')

        self.ssl = results["ssl"]
        header = results["header"]
        proxy = results["proxy"]

        self.header, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JBoss", "开始检测Jboss-Rce......")
            OutPrintInfo("JBoss", "开始检测Jboss-Rce-Poc1......")
        self._jboss_wsq(url)
        if not self.batch:
            OutPrintInfo("JBoss", "开始检测Jboss-Rce-Poc2......")
        self._jboss_rce(url)
        if not self.batch:
            OutPrintInfo("JBoss", "开始检测Jboss-Rce-Poc3......")
        self._jboss_rce2(url)
        if not self.batch:
            OutPrintInfo("JBoss", "开始检测Jboss-Rce-Poc4......")
        self._jboss_rce3(url)
        if not self.batch:
            OutPrintInfo("JBoss", "开始检测Jboss-Rce-Poc5......")
        self._jboss_rce4(url)

        if not self.batch:
            OutPrintInfo("JBoss","Jboss-Rce检测结束")

