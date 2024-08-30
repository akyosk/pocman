# import requests
# from bs4 import BeautifulSoup
import random
import time
from shodan import Shodan
from rich.progress import Progress
from rich.prompt import Prompt
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr,OutPrintInfoSuc
from pub.com.loadyamlset import ConfigLoader

shodan_api = ConfigLoader().get_values()["shodan-api"]


class ShodanWork:
    def __init__(self):
        self.__res_list = []
        self.__exit_num = 0
        self.__shodan_filename = ""
    def check_over(self,lens):
        if lens == len(self.__res_list):
            self.__exit_num += 1
            return False
        return True
    def run(self,page):
        req_nums = len(self.__res_list)
        try:
            api = Shodan(shodan_api)
            res = api.search(query=self.search, facets='country,org',page=int(page))

            for i in res['matches']:
                res_q = i['ip_str'] + ":" + str(i['port'])
                if res_q not in self.__res_list:
                    with open(f"./result/{self.__shodan_filename}", "a") as w:
                        w.write(res_q + "\n")
                    self.__res_list.append(res_q)
            if self.check_over(req_nums):
                OutPrintInfoSuc("Shodan", f"第 [b bright_red]{str(page)}[/b bright_red] 页爬取完成 [b green]:)")
            else:
                OutPrintInfoSuc("Shodan", f"第 [b bright_red]{str(page)}[/b bright_red] 页爬取完成,检测到数据均为重复数据 [b yellow]:^")


            return True

            # else:
            #     OutPrintInfo("Shodan", f"[b yellow]第{str(page)}页无返回结果 :(")
            #     return False
        except Exception:
            OutPrintInfo("Shodan", f"[b yellow]第 {str(page)} 页查询出错 :(")
            return False
    def nums(self,query):
        api = Shodan(shodan_api)
        try:
            res = api.search(query=query, facets='country,org', page=1)
            if "total" in res:
                OutPrintInfoSuc("Shodan", f"{query}搜索到 [b magenta]{str(res['total'])}[/b magenta] 个相关结果 [b green]:)")
                return True
            else:
                OutPrintInfo("Shodan",
                                f"[b yellow]{query} 未搜索到相关结果 :(")
                return False
        except Exception:
            OutPrintInfo("Shodan", f"[b yellow]shodan请求出错 :(")
            return False
    def file_num(self):
        return random.randint(100000,999999)
    def main(self,target):
        search = target['query'].strip()
        errorpass = int(target['pass'])
        self.search = search

        # threads = int(target['threads'])
        # pages = int(target[4])
        self.__shodan_filename = "shodan_"+str(self.file_num())+".txt"
        OutPrintInfo("Shodan", "开始通过Shodan获取搜索信息反馈...")
        if not self.nums(search):
            return
        OutPrintInfo("Shodan", "[b yellow]Shodan官方API不支持多线程 :(")
        OutPrintInfo("Shodan", "默认一页[b bright_red]100[/b bright_red]条页面展示数据")
        OutPrintInfo("Shodan", "根据返回的数据量除以[b bright_red]100[/b bright_red]就是爬取的页数")
        OutPrintInfo("Shodan", "普通会员只能爬取前[b bright_red]20[/b bright_red]页!!!!!!")
        pages = Prompt.ask("[b magenta]输入需要查询到页数")
        OutPrintInfo("Shodan", f"开始搜索[b bright_cyan]{search}[/b bright_cyan]相关信息...")
        with Progress(transient=True) as progress:
            tasks = progress.add_task("[b magenta]爬取进行中...",total=int(pages))
            numss = 0
            for page in range(1, int(pages)):
                if not self.run(page):
                    numss += 1

                progress.update(tasks,advance=1)
                if self.__exit_num == 5:
                    OutPrintInfo("Shodan", f"[b yellow]检测到多次查询到重复数据,疑是页数输入过量,程序自动退出 :(")
                    break
                if numss == errorpass:
                    OutPrintInfo("Shodan", f"[b yellow]检测到多次搜索搜索无结果,程序自动退出 :(")
                    break
                time.sleep(1)

        if self.__res_list:
            # OutPrintInfo("Shodan", "开始导出文件...")
            # with open("./result/shodan.txt","a") as w:
            #     for domains in self.__res_list:
            #         w.write(domains+"\n")
            OutPrintInfo("Shodan", f"共导出信息 [b bright_red]{len(self.__res_list)}[/b bright_red] 条")
            OutPrintInfo("Shodan", f"文件保存与 [b bright_red]result/{self.__shodan_filename}")

        else:
            OutPrintInfo("Shodan", "[b yellow]未搜索到查询结果 :(")
