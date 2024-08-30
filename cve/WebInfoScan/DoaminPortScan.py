#! /usr/bin/python3
# -*- coding: utf-8 -*-

import requests
from pub.com.outprint import OutPrintInfo
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor,wait
from rich.progress import Progress
from pub.com.reqset import ReqSet
import urllib3
urllib3.disable_warnings()

class DoaminScanProt():
# web端口信息
    def _ip_port(self, urls, port):
        url = urls + f":{str(port)}"
        try:
            resp = requests.get(url,headers=self.header,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if resp.status_code == 200:

                OutPrintInfo("Doamin-PORT",f"URL [b bright_red]{self._ip}[/b bright_red]  PORT [b bright_red]{port}[/b bright_red]")
        except Exception as e:
            pass

        # return result
    # 端口扫描
    def main(self,result):
        OutPrintInfo("Domain-PORT","开始扫描端口信息...")
        self._ip = result["url"].strip("/ ")
        nums = int(result["nums"])
        header = result["header"]
        self.ssl = result["ssl"]
        proxy = result["proxy"]
        self.timeout = int(result["timeout"])
        threads = int(result["threads"])
        self.header, self.proxy = ReqSet(header=header, proxy=proxy)
        with Progress(transient=True) as progress:
            tasks = progress.add_task("[b green] 端口扫描中...",total=nums)
            with ThreadPoolExecutor(threads) as pool:
                futures = [pool.submit(self._ip_port, self._ip, port) for port in range(1,nums)]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    progress.update(tasks,advance=1)
            wait(futures)

        OutPrintInfo("Domain-PORT","端口信息扫描结束")
