#! /usr/bin/python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor, wait,as_completed
from bs4 import BeautifulSoup
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
from rich import print as rprint
from requests import RequestException
from rich.progress import Progress


urllib3.disable_warnings()

class Dirsearch:
    def __init__(self):
        self.__url = None

    def __domain_scan(self, url):
        try:
            response = requests.head(url=url, headers=self.header, verify=self.verify,proxies=self.proxy)
            if response.status_code == 200 and response.url == self.__url:
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string
                contents = len(response.text)
                rprint(f"[[blue]Dir[/blue]]:{url}\t[[blue]Title[/blue]]:{str(title.strip())}\t[[blue]响应长度[/blue]]:{str(contents)}")
            # elif response.status_code == 302:
            #     soup = BeautifulSoup(response.text, 'html.parser')
            #     title = soup.title.string
            #     contents = len(response.text)
            #     rprint(
            #         f"[[blue]302[/blue]]:{url}\t[[blue]Title[/blue]]:{str(title.strip())}\t[[blue]响应长度[/blue]]:{str(contents)}")
        except RequestException as e:
            pass



    def main(self, results):
        self.__url = results["url"].strip('/ ')
        OutPrintInfo("Dirsearch", f"开始枚举 {self.__url} 路径...")
        threads = int(results["threads"])
        head = results["header"]
        self.verify = results["ssl"]
        proxy = results["proxy"]
        self.header,self.proxy = ReqSet(header=head,proxy=proxy)
        url_list = []

        with open('./dict/dirsearch.txt',"r") as f:
            for i in f:
                if i:
                    url_list.append(self.__url + "/" + i.strip())
        # spinner = Spinner("earth")
        # with Live(auto_refresh=False) as live:
        #     with ThreadPoolExecutor(int(threads)) as pool:
        #         futures = [pool.submit(self.__domain_scan, res_url) for res_url in url_list]
        #         for future in futures:
        #             while not future.done():
        #                 live.update(spinner)
        #                 live.refresh()
        #     # pool.shutdown()
        #     wait(futures)
        with Progress(transient=True) as progress:
            tasks = progress.add_task("[b cyan]子域名搜索...",total=len(url_list))
            with ThreadPoolExecutor(int(threads)) as pool:
                futures = [pool.submit(self.__domain_scan, res_url) for res_url in url_list]
                for future in as_completed(futures):
                    future.result()
                    progress.update(tasks,advance=1)
            wait(futures)

        OutPrintInfo("Dirsearch", "Web路径枚举结束")

