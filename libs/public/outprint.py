#!/user/bin/env python3
# -*- coding: utf-8 -*-
from rich import print
def OutPrintInfoErr(data):
    # print(Fore.RED+f"{Style.RESET_ALL} 程序不能执行该命令: [{Fore.LIGHTRED_EX}{str(data)}{Style.RESET_ALL}]")
    # print(f"[[bold bright_red]Woring[/bold bright_red]] :pile_of_poo:程序不能执行该命令 -> :exclamation::exclamation::exclamation: [bold red]{data}[/bold red]")
    print(f"[[bold bright_red]Woring[/bold bright_red]] :pile_of_poo:程序不能执行该命令 -> [bold red]:exclamation: {data} :exclamation: ")
def OutPrintInfo(name,data):
    # print(f":star: [[blue]{name}[/blue]]\t:lock:[bright_blue]{data}[/bright_blue]")
    print(f"[[b bright_blue]{name}[/b bright_blue]]\t:fire:[blue]{data} ")
