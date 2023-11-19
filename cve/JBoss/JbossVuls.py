#! /usr/bin/python3
# -*- coding: utf-8 -*-
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
from concurrent.futures import ThreadPoolExecutor,wait,as_completed
from rich.progress import Progress
import urllib3
urllib3.disable_warnings()
class JbossVulsScan:
    def _jboss_wsq(self, urls):
        # print(url)
        url = urls + '/jmx-console'
        try:
            response = requests.get(url=url, headers=self.header, verify=self.ssl, timeout=3, proxies=self.proxy)
            if response.status_code == 200 and '404' not in response.text:
                OutPrintInfo("JBoss",f"存在jboss未授权，默认密码[b bright_red]admin/admin[/b bright_red]")
                OutPrintInfo("JBoss",f"[b bright_red]Url {url}")
        except Exception as e:
            pass

    def _jboss_rce3(self, url):
        res_url = url + "/invoker/JMXInvokerServlet"
        try:
            response = requests.head(res_url, headers=self.header, verify=self.ssl, proxies=self.proxy)  # 发送HEAD请求获取响应头信息
            content_type = response.headers.get('content-type', '')
            if 'application/octet-stream' in content_type or 'application' in content_type:
                OutPrintInfo("JBoss",f"[b bright_red]存在Jboss-Rce,cve-2015-7501,若访问网站下载文件则存在漏洞 URL {res_url}")
        except Exception as e:
            pass

    def _jboss_rce(self, url):
        # print(url)
        try:
            res_url = f"{url}/invoker/readonly"
            # print(res_url)
            response = requests.get(url, headers=self.header, proxies=self.proxy, verify=self.ssl, timeout=5)
            if response.status_code == 500:
                OutPrintInfo("JBoss",f"[b bright_red]响应码为500存在jboss-CVE-2017-12149-rce,工具https://github.com/yunxu1/jboss-_CVE-2017-12149，网站位置 {res_url}")
        except Exception as e:
            pass

    def _jboss_rce4(self, url):
        res_url = url + "/invoker/EJBInvokerServlet"
        try:
            response = requests.head(res_url, headers=self.header, verify=self.ssl, proxies=self.proxy)  # 发送HEAD请求获取响应头信息
            content_type = response.headers.get('content-type', '')
            if 'application/octet-stream' in content_type or 'application' in content_type:
                OutPrintInfo("JBoss",f"[b bright_red]存在Jboss-Rce,cve-2013-4810,若访问网站下载文件则存在漏洞 {res_url}")

        except Exception as e:
            pass

    def _jboss_rce2(self, url):
        try:
            res_url = f"{url}/jbossmq-httpil/HTTPServerILServlet"
            response = requests.get(url, headers=self.header, proxies=self.proxy, verify=self.ssl, timeout=5)
            response.encoding = response.apparent_encoding
            if 'This is the JBossMQ HTTP-IL' in response.text:
                OutPrintInfo("JBoss",f"[b bright_red]存在jboss-CVE-2017-7504,工具https://github.com/joaomatosf/JavaDeserH2HC，网站位置 {res_url}")
        except Exception as e:
            pass

    def main(self, results):
        url = results[0].strip('/ ')
        threads = int(results[1])
        OutPrintInfo("JBoss","开始检测Jboss-Rce......")
        self.ssl = results[2]
        header = results[3]
        proxy = results[4]

        poc_list = [
            self._jboss_wsq,
            self._jboss_rce,
            self._jboss_rce2,
            self._jboss_rce3,
            self._jboss_rce4,
        ]
        reqset = ReqSet(header=header,proxy=proxy)
        self.proxy = reqset["proxy"]
        self.header = reqset["header"]
        with Progress(transient=True) as progress:
            tasks = progress.add_task("[b cyan]检测Jboss-Rce...",total=len(poc_list))
            with ThreadPoolExecutor(threads) as pool:
                futures = [pool.submit(jobs, url) for jobs in poc_list]
                for future in as_completed(futures):
                    future.result()
                    progress.update(tasks,advance=1)
            wait(futures)
        OutPrintInfo("JBoss","Jboss-Rce检测结束")

