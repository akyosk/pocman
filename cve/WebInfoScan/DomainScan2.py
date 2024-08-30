#! /usr/bin/python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
from bs4 import BeautifulSoup
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
from rich import print as rprint
from requests import RequestException
# from rich.spinner import Spinner
from rich.progress import Progress
# from rich.live import Live


urllib3.disable_warnings()

class ScanDomain:
    def __init__(self):
        self.__url = None

    def __domain_scan(self, url):
        try:
            response = requests.get(url="https://" + url, headers=self.header, verify=self.verify,proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string
                contents = len(response.text)
                rprint(f"[[blue]Domain[/blue]]:https://{url}\t[[blue]Title[/blue]]:{str(title.strip())}\t[[blue]响应长度[/blue]]{str(contents)}")
        except RequestException as e:
            pass



    def main(self, results):
        if '://' in results["domain"]:
            OutPrintInfo("Subdomain", '请输入不包含服务头的域名')
            return
        else:
            self.__url = results["domain"].strip('/ ')
        OutPrintInfo("Subdomain", f"开始枚举[b bright_red]{self.__url}[/b bright_red]子域名......")
        threads = int(results["threads"])
        head = results["header"]
        self.verify = results["ssl"]
        proxy = results["proxy"]
        self.header, self.proxy = ReqSet(header=head, proxy=proxy)
        url_list = []

        with open('./dict/subdomain.txt', encoding="utf-8") as f:
            for i in f:
                if i:
                    url_list.append(i.strip() + '.' + self.__url)
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
            tasks = progress.add_task("[b cyan]子域名枚举中...",total=len(url_list))
            with ThreadPoolExecutor(int(threads)) as pool:
                futures = [pool.submit(self.__domain_scan, res_url) for res_url in url_list]
                for future in as_completed(futures):
                    future.result()
                    progress.update(tasks,advance=1)
                # for future in futures:
                #     while not future.done():
                #         live.update(spinner)
                #         live.refresh()
            # pool.shutdown()
            wait(futures)

        OutPrintInfo("Subdomain", "子域名枚举结束")

