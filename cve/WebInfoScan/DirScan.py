#! /usr/bin/python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor, wait
from bs4 import BeautifulSoup
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
from rich import print as rprint
from requests import RequestException
from rich.spinner import Spinner
from rich.live import Live


urllib3.disable_warnings()

class Dirsearch:
    def __init__(self):
        self.__url = None

    def __domain_scan(self, url):
        try:
            response = requests.get(url=url, headers=self.header, verify=self.verify,proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string
                contents = len(response.text)
                rprint(f"[[blue]Dir[/blue]]:{url}\t[[blue]Title[/blue]]:{str(title.strip())}\t[[blue]响应长度[/blue]]:{str(contents)}")
        except RequestException as e:
            pass



    def main(self, results):
        self.__url = results[0].strip('/ ')
        OutPrintInfo("Dirsearch", f"开始枚举[b bright_red]{self.__url}[/b bright_red]路径......")
        threads = results[1]
        head = results[2]
        self.verify = results[3]
        proxy = results[4]
        req = ReqSet(header=head,proxy=proxy)
        self.header = req["header"]
        self.proxy = req["proxy"]
        url_list = []

        with open('./dict/dirsearch.txt',"r") as f:
            for i in f:
                if i:
                    url_list.append(self.__url + "/" + i.strip())
        spinner = Spinner("earth")
        with Live(auto_refresh=False) as live:
            with ThreadPoolExecutor(int(threads)) as pool:
                futures = [pool.submit(self.__domain_scan, res_url) for res_url in url_list]
                for future in futures:
                    while not future.done():
                        live.update(spinner)
                        live.refresh()
            # pool.shutdown()
            wait(futures)

        OutPrintInfo("Dirsearch", "Web路径枚举结束")

