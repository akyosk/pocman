#! /usr/bin/python3
# -*- coding: utf-8 -*-

import time
import aiohttp
import asyncio
from pub.com.outprint import OutPrintInfo
from rich import print as rprint

class DomainScanInfo:
    def __init__(self):
        self.nums = 1
        self.ssl = None
    async def detch(self,domain,base_url):
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60"}
        resurl = f"https://{domain}.{base_url}/"
        self.nums += 1
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(resurl, timeout=30,ssl=False,headers=headers) as response:
                    if response.status == 200:
                        OutPrintInfo("Subdomain", resurl)
        except Exception as e:
            pass

    async def run(self,url):
        with open('./dict/subdomain.txt', 'r') as f:
            tasks = [self.detch(domain.strip(),url) for domain in f]
            await asyncio.gather(*tasks)
            # await asyncio.sleep(3)

    def main(self,opts):
        OutPrintInfo("Subdomain", "采用[bold bright_red]async[/bold bright_red]实现")
        OutPrintInfo("Subdomain", "开始爆破子域名......")
        start = time.time()
        url = opts[0]
        self.ssl = opts[1]
        asyncio.run(self.run(url))
        end = time.time()
        OutPrintInfo("Subdomain", f"共爆破子域名个数[bold bright_red]{str(31287)}[/bold bright_red]个")
        OutPrintInfo("Subdomain", f"共花费[bold bright_red]{str(end-start)}[/bold bright_red]s")
