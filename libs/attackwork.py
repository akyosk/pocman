#!/user/bin/env python3
# -*- coding: utf-8 -*-
from set.config import threads,timeout,cookie,ssl,ua,proxy,url,ceye_dns,ceye_api
from libs.outprint import OutPrintInfoErr
from libs import batch
from rich import print as rprint
from libs.nowtime import Time
from rich.prompt import Prompt
from attack.Attack import AT_RUN_WORK
import sys
class Attack_Work:
    def __init__(self):
        self.__attack_work_canshu = {
            "url": url,
            "header": ua,
            "cookie": cookie,
            "threads":int(threads),
            "ssl": ssl,
            "proxy":proxy,
            "timeout": int(timeout),
            "max": 50000,
            "ceyeapi":ceye_api,
            "ceyedns":ceye_dns,
            "*Tips*": "max为网页爬取到最大值"
        }
    def opts(self):#程序第二步
        opts = Prompt.ask(f"[:eye:][[bold bright_blue]{Time()}[/bold bright_blue]]-([bold bright_red]POCMAN[/bold bright_red])-[b blue]ATTACK[/b blue](:gun:)")
        return opts
    def __show(self):
        for k,v in self.__attack_work_canshu.items():
            if k != "batch_work" and k != "file":
                k = str(k)
                q = "--->>>"
                v = str(v)
                rprint(f"[bold blue]{k:<15}[/bold blue]\t[bold]{q:<15}[/bold]\t[bright_blue]{v}[/bright_blue]")

    def __listOpt(self,opts):
        try:
            opt_list = opts.split(" ")
            if len(opt_list) != 2:
                OutPrintInfoErr(opts)
                return

            key = opt_list[0]
            if key in self.__attack_work_canshu:
                self.__attack_work_canshu[key] = opt_list[1]
        except Exception as e:
            OutPrintInfoErr(e)


    def main(self):
        self.__show()
        while True:
            cmd = self.opts()
            if cmd == "exit":
                sys.exit()
            elif cmd == "run":
                AT_RUN_WORK().main(self.__attack_work_canshu)
            elif cmd == "option" or cmd == "options":
                self.__show()
            elif cmd == "search":
                break
            elif cmd == "batch":
                batch.BatchInputCheck().main()
                break
            elif cmd == "option" or cmd == "options":
                self.__show()
            else:
                self.__listOpt(cmd)




