#! /usr/bin/python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from bs4 import BeautifulSoup
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
import pandas as pd
from requests import RequestException
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor,wait,as_completed



urllib3.disable_warnings()

class ScanDomain:

    def __domain_scan(self, url):
        try:
            response = requests.get(url="https://" + url, headers=self.header, verify=self.verify,proxies=self.proxy,timeout=self.timeout)

            if response.status_code == 200:
                response.encoding = response.apparent_encoding
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string
                contents = len(response.text)
                OutPrintInfo("Domain",f"[[blue]Domain[/blue]]:https://{url}\t[[blue]Title[/blue]]:{str(title.strip())}\t[[blue]响应长度[/blue]]{str(contents)}")
                data = {
                    "URL": url,
                    "Title": str(title.strip()),
                    "Contents": str(contents),
                }
                index = [1]
                df = pd.DataFrame(data,index=index)
                df.to_csv("./result/domainScan.csv",index=False,header=False,mode="a")
        except RequestException as e:
            pass



    def main(self, results):
        # OutPrintInfo("Subdomain", f"开始枚举[b bright_red]{self.__url}[/b bright_red]子域名......")
        url = results[0].strip("/ ")
        if "://" in url:
            url = url.split("://")[-1]
        head = results[1]
        self.verify = results[2]
        proxy = results[3]
        self.timeout = int(results[4])
        threads = int(results[5])
        req = ReqSet(header=head)
        self.header = req["header"]
        self.proxy = {"http":proxy,"https":proxy}
        self.__domain_scan(url)
        url_list = []
        with open('./dict/subdomain.txt', encoding="utf-8") as f:
            for i in f:
                if i:
                    url_list.append(i.strip() + '.' + url)

        # with tqdm(total=len(url_list),desc=url) as pbar:
        with ThreadPoolExecutor(int(threads)) as pool:
            futures = [pool.submit(self.__domain_scan, res_url) for res_url in url_list]
            for future in as_completed(futures):
                future.result()
                    # pbar.update(1)
        wait(futures)



        # OutPrintInfo("Subdomain", "子域名枚举结束")

