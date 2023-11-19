#! /usr/bin/python3
# -*- coding: utf-8 -*-
import concurrent.futures
import datetime
import requests
import urllib3
import time
from concurrent.futures import ThreadPoolExecutor,wait
from rich.progress import Progress
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()
class LogScan:
    def __init__(self):
        self.proxy = None
        self.header = None
        self.ssl = None

    def __log(self, new_url):
        try:
            response = requests.get(url=new_url, headers=self.header, verify=self.ssl, timeout=3, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            # print(new_url)
            if response.status_code == 200 and response.url == new_url:
                if "RunTime" in response.text:
                    OutPrintInfo("Log", f"[b bright_red]存在日志泄漏 {new_url}")
                else:
                    OutPrintInfo("Log", f"[b bright_red]可能存在日志泄漏 {new_url}")
        except Exception as e:
            pass

    def main(self, results):
        url = results[0].strip('/ ')
        threads = int(results[1])
        header = results[2]
        proxy = results[3]
        self.ssl = results[4]
        reqset = ReqSet(header=header,proxy=proxy)
        self.header = reqset["header"]
        self.proxy = reqset["proxy"]

        OutPrintInfo("Log", "开始检测日志泄漏......")
        # 获取当前日期和时间
        now = datetime.datetime.now()

        # 提取年份的最后两位
        year = now.year % 100

        # 获取月份，并在单数前面添加前导零
        month = f"{now.month:02d}"

        # 获取日期，并在单数前面添加前导零
        day = f"{now.day:02d}"

        current_year = datetime.datetime.now().year

        url_list = [
            url + f'/Application/Runtime/Logs/Home/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Admin/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/User/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Common/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Api/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Test/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Backend/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/user/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/admin/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/common/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Service/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Exp/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Ext/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/App/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/test/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/home/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/Home/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/Application/Runtime/Logs/Home/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/Application/Runtime/Logs/Home/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/Runtime/Logs/Home/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Runtime/Logs/Home/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/Runtime/Logs/Home/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/Runtime/Logs/Home/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/Application/Runtime/Logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Application/Runtime/Logs/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/Application/Runtime/Logs/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/Application/Runtime/Logs/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/Runtime/Logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/App/Runtime/Logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Runtime/Logs/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/Runtime/Logs/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/Runtime/Logs/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/application/runtime/logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/application/runtime/logs/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/application/runtime/logs/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/application/runtime/logs/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/runtime/logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/runtime/logs/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/runtime/logs/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/runtime/logs/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/Log/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Log/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/Log/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/Log/{str(current_year) + str(month)}/{str(day)}_sql.log',
            url + f'/log/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/log/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/log/{str(current_year) + str(month)}/{str(day)}_error.log',
            url + f'/log/{str(current_year) + str(month)}/{str(day)}_sql.log',
        ]
        time.sleep(1)
        with Progress(transient=True) as progress:
            tasks = progress.add_task("[b cyan]搜索日志文件...",total=len(url_list))
            with ThreadPoolExecutor(threads) as pool:
                futures = [pool.submit(self.__log, work) for work in url_list]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    progress.update(tasks,advance=1)
            wait(futures)
        OutPrintInfo("Log", "日志泄漏检测结束")