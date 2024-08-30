#!/user/bin/env python3
# -*- coding: utf-8 -*-
from rich import print as rp

# rich emoji输出
rich_flag = False

def Opts(flag):
    from pub.com.nowtime import Time
    from colorama import Fore,Style
    # opts = Prompt.ask(
    #     f"[[bold bright_blue]{Time()}[/bold bright_blue]]-([bold bright_red]POCMAN[/bold bright_red])-[b blue]SEARCH[/b blue]")
    opts = input(Fore.BLUE+ Style.BRIGHT + f"[{Time()}]-(POCMAN)-{flag}# " + Fore.RESET + Style.RESET_ALL)
    history_file = "log/history.log"
    with open(history_file, 'a') as f:
        f.write("[RunTime] | " + Time() + " | --->>> " + opts + '\n')
        if opts == "exit":
            f.write("| END |\n")
    return opts
def YamlPocErr(data):
    if rich_flag:
        rp(f"[[bold yellow]Sorry[/bold yellow]] :bomb:当前Yaml-Poc请求框架无法识别该脚本并执行 -> [bold red] {data} ")
    else:
        rp(f"[[bold yellow]Sorry[/bold yellow]] 当前Yaml-Poc请求框架无法识别该脚本并执行 -> [bold red] {data} ")

def YamlPrintSuc(data):
    def rich_style():
        severity = data["severity"].lower()
        if severity == "high":
            color = "bright_red"
        elif severity == "info":
            color = "bright_green"
        else:
            color = "bright_manager"
        rid = f"[[bold cyan]{data['id'].upper()}[/bold cyan]]"
        rse = f"[[bold {color}]{data['severity'].upper()}[/bold {color}]]"
        return rid, rse

    rid, rse = rich_style()
    rp(f"[[bold red]SUCCESS[/bold red]]\t :gun:{rid + rse + data['url']} " if rich_flag else f"[[bold bright_red]SUCCESS[/bold bright_red]]\t {rid + rse + data['url']} ")


def OutPrintInfoErr(data):
    if rich_flag:
        rp(f"[[bold bright_red]Woring[/bold bright_red]] :pile_of_poo:输入命令未成功执行 -> [bold red] {data}  ")
    else:
        rp(f"[[bold bright_red]Woring[/bold bright_red]] 输入命令未成功执行 -> [bold red] {data} ")
def NoSearchRes(data):
    if rich_flag:
        rp(f"[[bold yellow]Nothing[/bold yellow]] :gun:未匹配到相关结果 -> [bold red] {data} ")
    else:
        rp(f"[[bold yellow]Nothing[/bold yellow]] 未匹配到相关结果 -> [bold red] {data} ")
def OutPrintInfo(name,data):
    if rich_flag:
        rp(f"{'[[b bright_blue]'+name+'[/b bright_blue]]':<50}\t:fire:[blue]{data} ")
    else:
        rp(f"{'[[b bright_blue]' + name + '[/b bright_blue]]':<50}\t[blue]{data} ")
def OutPrintInfoSuc(name,data):
    if rich_flag:
        rp(f"{'[[b bright_blue]'+name+'[/b bright_blue]]':<50}\t:fire:[[b bright_red]SUCCESS[/b bright_red]][blue]{data} ")
    else:
        rp(f"{'[[b bright_blue]' + name + '[/b bright_blue]]':<50}\t[[b bright_red]SUCCESS[/b bright_red]][blue]{data} ")
def OutPrintInfoR(name,data):
    if rich_flag:
        rp(f"{'[[b bright_blue]'+name+'[/b bright_blue]]':<50}\t:fire:[blue]{data}                                                      ", end="\r")
    else:
        rp(f"{'[[b bright_blue]' + name + '[/b bright_blue]]':<50}\t[blue]{data}                                                      ",end="\r")
def TreadsWorkP():
    OutPrintInfo("Batch", "注意批量任务目前只支持[b bright_red]URL[/b bright_red]格式")
    OutPrintInfo("Batch",
                 "注意批量任务目标格式应安装Poc提示对应目标格式([b bright_red]Url/Domain/IP[/b bright_red])")
    OutPrintInfo("Batch", "注意批量任务目前需将执行文件保存于[b bright_red]batch[/b bright_red]文件下")

    OutPrintInfo("Batch", "注意批量任务默认执行文件为[b bright_red]batch/url.txt[/b bright_red]")

    OutPrintInfo("Batch", "正在加载任务... [b bright_green]:)")
# 启动程序加载poc输出格式
def PocPrint(version,ip,pocs,at_pocs,yaml_pocs,nums):
    if rich_flag:
        rp(f":eye:[b bright_red]禁止非法操作,工具只提供学习参考,违者后果自负:^")
        rp(
            f":fire:[bold red]Author: [b bright_red]akyo[/b bright_red]\tVersion: [b bright_red]{version}[/b bright_red][/bold red]")
        rp(f":lock:[bold magenta]{ip.strip()}[/bold magenta]")
        rp(f":smile:[b cyan]共收录内置POC [b bright_red]{pocs}[/b bright_red] 个[/b cyan]")
        rp(
            f":+1:[b cyan]共收录Batch-POC [b bright_red]{at_pocs}[/b bright_red] 个[/b cyan]")
        rp(
            f":boom:[b cyan]共收录Yaml-POC [b bright_red]{yaml_pocs}[/b bright_red] 个[/b cyan]")
        if nums:
            rp(
                f":gun:[b cyan]共 [b bright_red]{nums}[/b bright_red] 个Yaml-POC加载出错 [/b cyan]")
    else:
        rp(f"[b bright_red]禁止非法操作,工具只提供学习参考,违者后果自负:^")
        rp(
            f"[bold red]Author: [b bright_red]akyo[/b bright_red]\tVersion: [b bright_red]{version}[/b bright_red][/bold red]")
        rp(f"[bold magenta]{ip.strip()}[/bold magenta]")
        rp(f"[b cyan]共收录内置POC [b bright_red]{pocs}[/b bright_red] 个[/b cyan]")
        rp(
            f"[b cyan]共收录Batch-POC [b bright_red]{at_pocs}[/b bright_red] 个[/b cyan]")
        rp(
            f"[b cyan]共收录Yaml-POC [b bright_red]{yaml_pocs}[/b bright_red] 个[/b cyan]")
        if nums:
            rp(
                f":gun:[b cyan]共 [b bright_red]{nums}[/b bright_red] 个Yaml-POC加载出错 [/b cyan]")
# Attack-Post输出格式
def ATPrintInfoPostSuc(url,vlun,data,body):
    from urllib.parse import urlparse
    rp(f"[b bright_red]ATTACK {vlun} SUCCESS AND VULN INFO:")
    rp(f"\t[b yellow]POST {urlparse(url).path}?{urlparse(url).query} HTTP/1.1")
    rp(f"\t[b yellow]Host: {urlparse(url).netloc}")
    for k,v in data.items():
        rp(f"\t[b yellow]{k}: {v}")
    rp(f"\t[b yellow] {body}\n")
# Attack-Get输出格式
def ATPrintInfoSuc(url,vlun,data):
    from urllib.parse import urlparse
    rp(f"[b bright_red]ATTACK {vlun} SUCCESS AND VULN INFO:")
    rp(f"\t[b yellow]GET {urlparse(url).path}?{urlparse(url).query} HTTP/1.1")
    rp(f"\t[b yellow]Host: {urlparse(url).netloc}")
    for k,v in data.items():
        rp(f"\t[b yellow]{k}: {v}")
    print()
def ATShowP(attack_work_canshu):
    for k, v in attack_work_canshu.items():
        if k not in {"batch_work", "file", "username", "password"}:
            rp(f"[bold blue]{k:<15}[/bold blue]\t[bold]--->>>[/bold]\t[bright_blue]{v}[/bright_blue]")
def SearchPrint(searchdict,flag):
    if flag == "BATCH":
        dir_value = searchdict["dir"]
        rp(f"[bold bright_blue]{'dir':<15}[/bold bright_blue]\t[bold]{'--->>>':<15}[/bold]\t[bright_blue]{dir_value}[/bright_blue]")
        for k, v in searchdict.items():  # 遍历下标，并输出需要参数
            if k != "batch_work" and k != "url" and k != "dir":
                k = str(k)
                q = "--->>>"
                v = str(v)
                # print(f"[{Fore.BLUE}{k}{Style.RESET_ALL}]\t--->>>\t[{Fore.BLUE}{v}{Style.RESET_ALL}]")
                rp(
                    f"[bold bright_blue]{k:<15}[/bold bright_blue]\t[bold]{q:<15}[/bold]\t[bright_blue]{v}[/bright_blue]")
        return
    for k, v in searchdict.items():  # 遍历下标，并输出需要参数
        if k != "batch_work" and k != "fofa" and k != "shodan":
            k = str(k)
            q = "--->>>"
            v = str(v)
            # print(f"[{Fore.BLUE}{k}{Style.RESET_ALL}]\t--->>>\t[{Fore.BLUE}{v}{Style.RESET_ALL}]")
            rp(
                f"[bold bright_blue]{k:<15}[/bold bright_blue]\t[bold]{q:<15}[/bold]\t[bright_blue]{v}[/bright_blue]")
def SearchYamlPrint(res_list):
    for k, v in res_list.items():
        q = "--->>>"
        rp(
            f"[bold blue]{k.lower():<15}[/bold blue]\t[bold]{q:<15}[/bold]\t[bright_blue]{v}[/bright_blue]")
def SearchYamlDataPrint(reslist):
    for k, v in reslist.items():
        k = str(k)
        q = "--->>>"
        v = str(v)
        rp(
            f"[bold blue]{k.lower():<15}[/bold blue]\t[bold]{q:<15}[/bold]\t[bright_blue]{v}[/bright_blue]")

def SearchResListPrint(searchList):
    rp("[b bright_blue]内置-POC")
    for num, i in enumerate(searchList):  # 输出search的结果
        formatted_name = str(i['name'])  # 设置边距让输出格式化输出 上下文对齐
        formatted_description = str(i['description'])
        rp(
            f"{'[[b bright_blue]' + str(num) + '[/b bright_blue]]' + '[b cyan]' + str(formatted_name) + '[/b cyan]':<80}[[bold bright_cyan]INFO[/bold bright_cyan]][b blue]{formatted_description}[/b blue]")


def SearchYamlResListPrint(searchList,yamlList):
    rp("[b blue]YAML-POC")
    for num, i in enumerate(yamlList):
        rp(
            f"{'[[b bright_blue]' + str(num + len(searchList)) + '[/b bright_blue]]' + '[b cyan]' + str(i[0]) + '[/b cyan]':<80}[[bold bright_cyan]INFO[/bold bright_cyan]][b blue]{i[1]}[/b blue]")
