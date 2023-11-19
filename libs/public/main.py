#!/user/bin/env python3
# -*- coding: utf-8 -*-
from time import sleep
from libs.public.inputcheck import inputCheck
from libs.public.getip import getIp
from set.pocset import modules
from set.batch_pocset import batch_modules
from rich import print as rprint
from rich.console import Console

class pocMain:
    def __options(self):
        console = Console()
        with console.status("[green] 开始启动程序...\n") as status:
            ip = getIp()
            sleep(1)
            if ip != "":
                status.stop()
                rprint(f":fire:[bold red]Author: [b bright_red]akyo[/b bright_red]\tVersion: [b bright_red]4.0.00[/b bright_red][/bold red]")
                rprint(f":lock:[bold magenta]{ip.strip()}[/bold magenta]")

                rprint(f":smile:[b bright_yellow]共收录POC [b bright_red]{self.__get_pocs()}[/b bright_red] 个[/b bright_yellow]")
                rprint(f":+1:[b bright_cyan]共收录Batch-POC [b bright_red]{self.__get_batch_pocs()}[/b bright_red] 个[/b bright_cyan]")

            else:
                status.stop()
                rprint(f":fire:[bold red]Author: [b bright_red]akyo[/b bright_red]\tVersion: [b bright_red]4.0.00[/b bright_red][/bold red]")
                rprint(f":smile:[b bright_yellow]共收录POC [b bright_red]{self.__get_pocs()}[/b bright_red] 个[/b bright_yellow]")
                rprint(f":+1:[b bright_cyan]共收录Batch-POC [b bright_red]{self.__get_batch_pocs()}[/b bright_red] 个[/b bright_cyan]")


    def __get_pocs(self):
        return len(modules)
    def __get_batch_pocs(self):
        return len(batch_modules)


    def main(self):
        self.__options()
        while True:
            inputCheck().main()

