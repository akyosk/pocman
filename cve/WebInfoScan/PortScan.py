#! /usr/bin/python3
# -*- coding: utf-8 -*-
import socket
from pub.com.outprint import OutPrintInfo
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor,wait
from rich.progress import Progress

class ScanProt():
    def __init__(self, ip=None):
        self._ip = ip
# web端口信息
    def _ip_port(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 超时
        s.settimeout(0.5)
        # 发起请求
        try:
            if s.connect_ex((ip, port)) == 0:
                OutPrintInfo("IP-PORT",f"IP [b bright_red]{self._ip}[/b bright_red]  PORT [b bright_red]{port}[/b bright_red]")
                s.close()
        except Exception as e:
            pass

        # return result
    # 端口扫描
    def main(self,result):
        OutPrintInfo("IP-PORT","开始扫描端口信息...")
        self._ip = result["ip"]
        nums = int(result["nums"])
        threads = int(result["threads"])
        with Progress(transient=True) as progress:
            tasks = progress.add_task("[b green] 端口扫描中...",total=nums)
            with ThreadPoolExecutor(threads) as pool:
                futures = [pool.submit(self._ip_port, self._ip, port) for port in range(1,nums)]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    progress.update(tasks,advance=1)
            wait(futures)

        OutPrintInfo("IP-PORT","端口信息扫描结束")
