#!/user/bin/env python3
# -*- coding: utf-8 -*-
from rich import print as rp
from urllib.parse import urlparse
def OutPrintInfoErr(data):
    # print(Fore.RED+f"{Style.RESET_ALL} 程序不能执行该命令: [{Fore.LIGHTRED_EX}{str(data)}{Style.RESET_ALL}]")
    # print(f"[[bold bright_red]Woring[/bold bright_red]] :pile_of_poo:程序不能执行该命令 -> :exclamation::exclamation::exclamation: [bold red]{data}[/bold red]")
    rp(f"[[bold bright_red]Woring[/bold bright_red]] :pile_of_poo:输入命令未成功执行 -> [bold red]:exclamation: {data} :exclamation: ")
def OutPrintInfo(name,data):
    # print(f":star: [[blue]{name}[/blue]]\t:lock:[bright_blue]{data}[/bright_blue]")
    rp(f"{'[[b bright_blue]'+name+'[/b bright_blue]]':<50}\t:fire:[blue]{data} ")
def OutPrintInfoSuc(name,data):
    rp(f"{'[[b bright_blue]'+name+'[/b bright_blue]]':<50}\t:fire:[[b bright_red]SUCCESS[/b bright_red]][blue]{data} ")

def ATPrintInfoSuc(url,vlun,data):
    rp(f"[b bright_red]ATTACK {vlun} SUCCESS AND VULN INFO:")
    rp(f"\t[b yellow]GET {urlparse(url).path}?{urlparse(url).query} HTTP/1.1")
    rp(f"\t[b yellow]Host: {urlparse(url).netloc}")
    for k,v in data.items():
        rp(f"\t[b yellow]{k}: {v}")
    print()
def OutPrintInfoR(name,data):
    # print(f":star: [[blue]{name}[/blue]]\t:lock:[bright_blue]{data}[/bright_blue]")
    rp(f"{'[[b bright_blue]'+name+'[/b bright_blue]]':<50}\t:fire:[blue]{data} ", end="\r")

def ATPrintInfoPostSuc(url,vlun,data,body):
    rp(f"[b bright_red]ATTACK {vlun} SUCCESS AND VULN INFO:")
    rp(f"\t[b yellow]POST {urlparse(url).path}?{urlparse(url).query} HTTP/1.1")
    rp(f"\t[b yellow]Host: {urlparse(url).netloc}")
    for k,v in data.items():
        rp(f"\t[b yellow]{k}: {v}")
    rp(f"\t[b yellow] {body}\n")


