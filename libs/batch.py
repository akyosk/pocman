#!/user/bin/env python3
# -*- coding: utf-8 -*-
import sys
from libs.nowtime import Time
from libs.outprint import OutPrintInfoErr,OutPrintInfo
from set.pocset import modules
from set.config import batch_work_file
from rich import print as rprint
from libs.attackwork import Attack_Work
from rich.prompt import Prompt
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor,wait,as_completed

class BatchInputCheck:
    # 输出样式
    # 程序的input样式（所有的input都是调用这个）
    def _opts(self):  # 程序第二步
        # opts = input(f"{Style.RESET_ALL}[{Fore.LIGHTBLUE_EX + Time() + Style.RESET_ALL}]-({Fore.LIGHTRED_EX}PocMan{Style.RESET_ALL})-{Fore.LIGHTGREEN_EX}${Style.RESET_ALL} :")
        opts = Prompt.ask(
            f"[:eye:][[bold bright_blue]{Time()}[/bold bright_blue]]-([bold bright_red]POCMAN[/bold bright_red])-[b blue]BATCH[/b blue](:bomb:)")
        return opts

    # 主函数
    def main(self):  # 程序第一步
        opts = self._opts()
        BatchOpts()._checkOpts(opts)  # 检测输入并且必须包含search才能执行，为exit推出
            
class BatchOpts:# 用于search检测
    def __init__(self):
        self.choose = None
        self.num = None

    def _checkOpts(self, opts):
        opt = opts.split(" ")
        if len(opt) != 2:
            if opts == "search":
                OutPrintInfoErr(
                    f"检测到只输入[[b yellow]{opt}[/b yellow]],脚本认定为返回[b magenta]Search[/b magenta]模式")
                return
            elif opts == "exit":
                sys.exit()
            elif opts == "attack":
                Attack_Work().main()
                return
            OutPrintInfoErr(opts)
            return
        elif opt != "" and "search" == opt[0]:
            self.__optWork(opt[1])  # 对程序search进行搜索
            return
        else:
            OutPrintInfoErr(opts)
            return
    # 多方调用这个函数不能reture
    def __optWork(self, opt):  # 程序第四步，开始遍历字典，搜索是否存在对应信息
        searchList = []

        for k in modules:  # 只遍历name与description一个是poc名称，一个是poc详情
            if "batch_work" in k["params"]:
                if opt.lower() in k["name"].lower() or opt.lower() in k["description"].lower():
                    searchList.append(k)
        if not searchList:# 判断是否为空
            OutPrintInfoErr(opt)
            BatchInputCheck().main()
        for num, i in enumerate(searchList): # 输出search的结果
            formatted_name = str(i['name']) # 设置边距让输出格式化输出 上下文对齐
            formatted_description = str(i['description'])

            # formatted_name = f"[[bold bright_cyan]{str(num)}[/bold bright_cyan]][bold bright_blue]{str(i['name'])}[/bold bright_blue]"  # 设置边距让输出格式化输出 上下文对齐
            # formatted_description = f"[[bold bright_cyan]INFO[/bold bright_cyan]][b blue]{str(i['description'])}[/b blue]"
            rprint(
                f"{'[[b bright_blue]' + str(num) + '[/b bright_blue]]' + '[b blue]' + str(formatted_name) + '[/b blue]':<80}[[bold bright_cyan]INFO[/bold bright_cyan]][b blue]{formatted_description}[/b blue]")

            # rprint(f"{formatted_name.ljust(10)}{formatted_description.ljust(50)}")

        if not self.__numOpt(searchList):  # 检测输入对下标是否正确
            return

        # del searchList[int(self.num)]["params"]["url"]
        searchList[int(self.num)]["params"]["dir"] = batch_work_file
        dir_value = searchList[int(self.num)]["params"]["dir"]
        rprint(f"[bold bright_blue]{'dir':<15}[/bold bright_blue]\t[bold]{'--->>>':<15}[/bold]\t[bright_blue]{dir_value}[/bright_blue]")
        for k, v in searchList[int(self.num)]["params"].items():  # 遍历下标，并输出需要参数
            if k != "batch_work" and k != "dir" and k != "url":
                k = str(k)
                q = "--->>>"
                v = str(v)
                # print(f"[{Fore.BLUE}{k}{Style.RESET_ALL}]\t--->>>\t[{Fore.BLUE}{v}{Style.RESET_ALL}]")
                rprint(
                    f"[bold bright_blue]{k:<15}[/bold bright_blue]\t[bold]{q:<15}[/bold]\t[bright_blue]{v}[/bright_blue]")
        self.__iputParse(searchList[int(self.num)])  # 修改需要的参数

    def __iputParse(self, reslist):  # 这里传的是已经筛选好的列表，可以直接进行赋值了
        while True:
            try:
                opts = BatchInputCheck()._opts()
                if not self.__exitAndOther(opts):  # 直接调用函数判断是否需要其他操作
                    break

                elif opts.lower() == "options" or opts.lower() == "option":
                    dir_value = reslist["params"]["dir"]
                    rprint(f"[bold bright_blue]{'dir':<15}[/bold bright_blue]\t[bold]{'--->>>':<15}[/bold]\t[bright_blue]{dir_value}[/bright_blue]")
                    for k, v in reslist["params"].items():
                        if k != "batch_work" and k != "dir" and k != "url":
                            k = str(k)
                            q = "--->>>"
                            v = str(v)
                            rprint(f"[bold blue]{k:<15}[/bold blue]\t[bold]{q:<15}[/bold]\t[bright_blue]{v}[/bright_blue]")

                elif opts.lower() == "run":
                    threads = None
                    OutPrintInfo("Batch","注意批量任务目前只支持[b bright_red]URL[/b bright_red]格式")
                    OutPrintInfo("Batch","注意批量任务目标格式应安装Poc提示对应目标格式([b bright_red]Url/Domain/IP[/b bright_red])")
                    OutPrintInfo("Batch", "注意批量任务目前需将执行文件保存于[b bright_red]batch[/b bright_red]文件下")

                    OutPrintInfo("Batch","注意批量任务默认执行文件为[b bright_red]batch/url.txt[/b bright_red]")

                    # values = list(reslist["params"].values())
                    # poc.main(values)
                    OutPrintInfo("Batch", "正在加载任务... [b bright_green]:)")
                    parsesss = reslist["params"]
                    for key in reslist["params"]:
                        value = parsesss[key]
                        if value == "False" or value == False or value == "false":

                            parsesss[key] = False
                        elif value == "True" or value == True or value == "true":

                            parsesss[key] = True
                        elif value == "None" or value == None or value == "none":

                            parsesss[key] = None
                    batch_url_list = []

                    work_urls = parsesss["dir"]
                    OutPrintInfo("Batch", f"指定任务文件为[b bright_red]{work_urls} ")
                    if "./" in work_urls:
                        with open(work_urls, "r") as f:
                            for req_url in f:
                                if req_url:
                                    if req_url.strip() not in batch_url_list:
                                        if "://" not in req_url.strip():
                                            batch_url_list.append("http://"+req_url.strip())
                                        else:
                                            batch_url_list.append(req_url.strip())
                    else:
                        with open(f"./{work_urls}","r") as f:
                            for req_url in f:
                                if req_url:
                                    if "://" not in req_url.strip():
                                        batch_url_list.append("http://" + req_url.strip())
                                    else:
                                        batch_url_list.append(req_url.strip())
                    OutPrintInfo("BATCH",f"共识别任务[b magenta]{str(len(batch_url_list))}[/b magenta]个")
                    poc = reslist["poc"]()
                    canShu = reslist["params"]
                    poc_req_list = []

                    try:
                        for p in batch_url_list:
                            copy_sj = canShu.copy()
                            # copy_sj["dir"]=p 传入参数列表
                            copy_sj["url"]=p # 传入字典
                            # 批量模式判断条件
                            copy_sj["batch_work"] = True
                            poc_req_list.append(copy_sj)

                    except Exception:
                        OutPrintInfoErr("该POC可能暂时不支持批量检测 :(")
                        return

                    if poc_req_list:
                        OutPrintInfo("Batch", "任务加载完成 [b bright_cyan];)")
                        try:
                            threads = int(Prompt.ask("[[b red]Batch[/b red]]\t[b yellow]输入运行线程数"))
                        except Exception:
                            OutPrintInfoErr(f"{threads} :(")
                            return
                        try:
                            if parsesss["proxy"]:
                                from libs.reqset import ReqSet
                                if not ReqSet(proxy=parsesss["proxy"]):
                                    return
                        except Exception as e:
                            OutPrintInfoErr(f"{e} :(")

                        with Progress(transient=True) as progress:
                            task = progress.add_task("[b green]批量任务执行中...",total=len(poc_req_list))
                            with ThreadPoolExecutor(threads) as pool:
                                # futures = [pool.submit(poc.main,list(poc_req.values())) for poc_req in poc_req_list] 传入参数列表
                                futures = [pool.submit(poc.main,poc_req) for poc_req in poc_req_list] # 直接传入字典
                                for future in as_completed(futures):
                                    future.result()
                                    progress.update(task,advance=1)
                            wait(futures)
                    else:
                        OutPrintInfoErr("未能在任务文件加载到任务 :(")
                        OutPrintInfo("Batch","请在[b bright_red]batch/url.txt[/b bright_red]进行核实")




                    # break 这里不用break可以继续操作
                else:
                    # 对多命令进行组合例如ping baidu.com
                    if len(opts.split(" ")) >= 2:# 直接进行赋值的
                        key = opts.split(" ")[0].strip()  # 键值对
                        if key == "url" or key == "fofa" or key == "batch_work":
                            OutPrintInfoErr(opts)
                        values = opts.split(" ")[1:]  # 键值对
                        value = " ".join(values)
                        # print(value)
                        f = False # 判断是否输入有误例如屏蔽shjgdh hdbg dhj jdh sdj或者shdgh hjg
                        for k, v in reslist["params"].items():
                            if key.lower() == k.lower():
                                reslist["params"][k] = value
                                f = True
                        if not f:
                            OutPrintInfoErr(opts)
                    else:
                        OutPrintInfoErr(opts)


            except Exception as e:
                OutPrintInfoErr(e)



    def __exitAndOther(self, opts):
        if opts == "exit":
            sys.exit()
        elif opts == "attack":
            Attack_Work().main()
            return
        elif "search" in opts:
            self._checkOpts(opts)
            return False
        return True

    def __numOpt(self, searchList):  # 主要检测输入对下标是否正确/判断是否进行其他操作
        flag = True
        while flag:
            self.choose = BatchInputCheck()._opts()
            if not self.__exitAndOther(self.choose):  # 直接调用函数判断是否需要其他操作
                break
            if " " not in self.choose.strip():
                self.num = self.choose
                try:
                    if searchList[int(self.num)]:  # 判断列表里是否存在该下标
                        flag = False
                except ValueError as e:
                    OutPrintInfoErr(e)

                except IndexError as e:
                    OutPrintInfoErr(e)
            else:
                if "use" == self.choose.split(" ")[0].lower():
                    try:
                        self.num = self.choose.split(" ")[1]
                        if searchList[int(self.num)]:  # 判断列表里是否存在该下标
                            flag = False
                    except ValueError as e:
                        OutPrintInfoErr(e)

                    except IndexError as e:
                        OutPrintInfoErr(e)
                else:
                    OutPrintInfoErr(self.choose)

        return self.num

