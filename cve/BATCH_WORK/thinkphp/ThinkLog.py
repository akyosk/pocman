#! /usr/bin/python3
# -*- coding: utf-8 -*-
import concurrent.futures
import datetime
import requests
import urllib3
import time
from concurrent.futures import ThreadPoolExecutor,wait
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
            response = requests.get(url=new_url, headers=self.header, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            # print(new_url)
            if response.status_code == 200 and response.url == new_url:
                if "RunTime" in response.text:
                    OutPrintInfo("Log", f"[b bright_red]存在日志泄漏 {new_url}")
                    with open("./result/thinkphpLog.txt", "a") as w:
                        w.write(f"存在日志泄漏 {new_url}\n")
                else:
                    OutPrintInfo("Log", f"[b bright_red]可能存在日志泄漏 {new_url}")
                    with open("./result/thinkphpLog.txt", "a") as w:
                        w.write(f"可能存在日志泄漏 {new_url}\n")
                return True
            return False
        except Exception as e:
            return False

    def main(self, results):
        url = results[0].strip('/ ')
        header = results[1]
        proxy = results[2]
        self.ssl = results[3]
        self.timeout = int(results[4])
        reqset = ReqSet(header=header)
        self.header = reqset["header"]
        self.proxy = {"http":proxy,"https":proxy}

        # OutPrintInfo("Log", "开始检测日志泄漏......")
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
            url + f'/Application/Runtime/Logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Runtime/Logs/Home/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/Runtime/Logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/App/Runtime/Logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/runtime/logs/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/runtime/log/{str(year)}_{str(month)}_{str(day)}.log',
            url + f'/runtime/logs/{str(current_year) + str(month)}/{str(day)}.log',
            url + f'/runtime/log/{str(current_year) + str(month)}/{str(day)}.log',
        ]
        for pos in url_list:
            if self.__log(pos):
                break
        # OutPrintInfo("Log", "日志泄漏检测结束")