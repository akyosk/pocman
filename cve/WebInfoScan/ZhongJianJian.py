#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import concurrent.futures
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor,wait
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.progress import Progress
urllib3.disable_warnings()

class ZhongJianJianScan:
    def run(self,dir):
        url = self.url + dir.strip()
        try:
            response = requests.head(url=url,headers=self.head,verify=self.verify,proxies=self.proxy)
            if response.status_code == 200 and response.url == url:
                OutPrintInfoSuc("WEB-DIR",f"Find: {url}")
            # elif response.status_code == 302:
            #     OutPrintInfoSuc("WEB-DIR", f"302: {url}")
        except Exception as e:
            pass
    def main(self,target):
        if "batch_work" in target:
            self.batch = target["batch_work"]
        else:
            self.batch = False
        if not self.batch:
            OutPrintInfo("WEB-DIR","开始扫描Web信息...")
        self.url = target["url"].strip('/ ')
        threads = int(target["threads"])
        self.verify = target["ssl"]
        head = target["header"]
        proxy = target["proxy"]

        self.head, self.proxy = ReqSet(header=head, proxy=proxy, bwork=self.batch)

        f = open('./dict/webDir.txt','r')
        poc = f.readlines()
        f.close()
        with Progress(transient=True) as progress:
            task = progress.add_task("[b cyan]扫描Web信息...",total=len(poc))
            with ThreadPoolExecutor(int(threads)) as pool:
                futures = [pool.submit(self.run,dir) for dir in poc]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    progress.update(task,advance=1)
            wait(futures)
        if not self.batch:
            OutPrintInfo("WEB-DIR","Web信息扫描结束")


