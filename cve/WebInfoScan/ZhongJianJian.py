#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import concurrent.futures
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor,wait
from fake_useragent import UserAgent
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
from rich.progress import Progress
urllib3.disable_warnings()
ua = UserAgent()

class ZhongJianJianScan:
    def run(self,dir):
        url = self.url + dir.strip()
        try:
            response = requests.get(url=url,headers=self.head,verify=self.verify,proxies=self.proxy)
            if response.status_code == 200:
                OutPrintInfo("WEB-DIR",f"Find {url}")
        except Exception as e:
            pass
    def main(self,target):
        OutPrintInfo("WEB-DIR","开始扫描Web信息...")
        self.url = target[0].strip('/ ')
        threads = target[1]
        self.verify = target[2]
        head = target[3]
        proxy = target[4]

        req = ReqSet(proxy=proxy,header=head)
        self.proxy = req["proxy"]
        self.head = req["header"]

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
        OutPrintInfo("WEB-DIR","Web信息扫描结束")


