#!/user/bin/env python3
# -*- coding: utf-8 -*-
import sys
from libs.public.nowtime import Time
from libs.public.outprint import OutPrintInfoErr
from set.pocset import modules
from libs.public.batch import BatchInputCheck
from rich import print as rprint
from rich.prompt import Prompt
class inputCheck:
    # 输出样式
    # 程序的input样式（所有的input都是调用这个）
    def opts(self):#程序第二步
        # opts = input(f"{Style.RESET_ALL}[{Fore.LIGHTBLUE_EX + Time() + Style.RESET_ALL}]-({Fore.LIGHTRED_EX}PocMan{Style.RESET_ALL})-{Fore.LIGHTGREEN_EX}${Style.RESET_ALL} :")
        opts = Prompt.ask(f"[[bold bright_blue]{Time()}[/bold bright_blue]]-([bold bright_red]PocMan[/bold bright_red])-[b blue]Search[/b blue][bold bright_red]@[/bold bright_red]")

        return opts
    # 主函数
    def main(self):#程序第一步
        opts = self.opts()

        searchOpts().checkOpts(opts)#检测输入并且必须包含search才能执行，为exit推出

class searchOpts:# 用于search检测
    def __init__(self):
        self.choose = None
        self.num = None
    # 对输入进行分类
    def checkOpts(self, opts):
        opt = self.__listOpt(opts)  # 将输入转化为列表，并且判断退出
        if opt != "" and "search" == opt[0]:
            self.__optWork(opt[1])  # 对程序search进行搜索
            return
        elif opts == "batch":
            BatchInputCheck().main()
            return
        else:
            OutPrintInfoErr(opts)
            return


    # 多方调用这个函数不能reture
    def __optWork(self, opt):  # 程序第四步，开始遍历字典，搜索是否存在对应信息
        searchList = []
        for k in modules:  # 只遍历name与description一个是poc名称，一个是poc详情
            if opt.lower() in k["name"].lower() or opt.lower() in k["description"].lower():
                searchList.append(k)
        if not searchList:# 判断是否为空
            OutPrintInfoErr(opt)
            inputCheck().main()
        for num, i in enumerate(searchList): # 输出search的结果
            formatted_name = str(i['name']).ljust(25)  # 设置边距让输出格式化输出 上下文对齐
            formatted_description = str(i['description']).ljust(35)

            # formatted_name = f"[[bold bright_cyan]{str(num)}[/bold bright_cyan]][bold bright_blue]{str(i['name'])}[/bold bright_blue]"  # 设置边距让输出格式化输出 上下文对齐
            # formatted_description = f"[[bold bright_cyan]INFO[/bold bright_cyan]][b blue]{str(i['description'])}[/b blue]"

            rprint(
                f"[[bold bright_cyan]{str(num)}[/bold bright_cyan]][bold bright_blue]{formatted_name}[/bold bright_blue][[bold bright_cyan]INFO[/bold bright_cyan]][b blue]{formatted_description}[/b blue]")
            # rprint(f"{formatted_name.ljust(10)}{formatted_description.ljust(50)}")
        self.__numOpt(searchList)  # 检测输入对下标是否正确
        for k, v in searchList[int(self.num)]["params"].items():  # 遍历下标，并输出需要参数
            k = str(k).ljust(15)
            q = "--->>>".ljust(15)
            v = str(v).ljust(15)
            # print(f"[{Fore.BLUE}{k}{Style.RESET_ALL}]\t--->>>\t[{Fore.BLUE}{v}{Style.RESET_ALL}]")
            rprint(
                f"[bold bright_blue]{k}[/bold bright_blue]\t[bold]{q}[/bold]\t[bright_blue]{v}[/bright_blue]")
        self.__iputParse(searchList[int(self.num)])  # 修改需要的参数

    def __iputParse(self, reslist):  # 这里传的是已经筛选好的列表，可以直接进行赋值了
        while True:
            try:
                opts = inputCheck().opts()
                if not self.__exitAndOther(opts):  # 直接调用函数判断是否需要其他操作
                    break
                elif opts.lower() == "options" or opts.lower() == "option":
                    for k, v in reslist["params"].items():
                        k = str(k).ljust(15)
                        q = "--->>>".ljust(15)
                        v = str(v).ljust(15)
                        rprint(f"[bold blue]{k}[/bold blue]\t[bold]{q}[/bold]\t[bright_blue]{v}[/bright_blue]")
                elif opts.lower() == "run":
                    parsesss = reslist["params"]
                    for key in reslist["params"]:
                        value = parsesss[key]
                        if value == "False" or value == False or value == "false":

                            parsesss[key] = False
                        elif value == "True" or value == True or value == "true":

                            parsesss[key] = True
                        elif value == "None" or value == None or value == "none":

                            parsesss[key] = None

                    values = list(reslist["params"].values())
                    # print(values)

                    poc = reslist["poc"]()
                    poc.main(values)
                    # break 这里不用break可以继续操作
                else:
                    # 对多命令进行组合例如ping baidu.com
                    if len(opts.split(" ")) >= 2:# 直接进行赋值的
                        key = opts.split(" ")[0].strip()  # 键值对
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
        elif opts == "batch":
            BatchInputCheck().main()
            return
        elif "search" in opts:
            self.checkOpts(opts)
            return False

        return True

    def __numOpt(self, searchList):  # 主要检测输入对下标是否正确/判断是否进行其他操作
        flag = True
        while flag:
            self.choose = inputCheck().opts()
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

    # 对输入进行检测
    def __listOpt(self, opts):  # 程序第三步，首先检测是否推出, 然后将输入按空格拆分为列表返回
        if opts == "exit":
            sys.exit()
        elif opts == "batch":
            return opts
        opts = opts.split(" ")
        if len(opts) == 2:
            return opts
        else:
            # OutPrintInfoErr(opts)
            return ""



