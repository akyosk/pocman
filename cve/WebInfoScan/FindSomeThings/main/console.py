import argparse
from cve.WebInfoScan.FindSomeThings.main import deal
from cve.WebInfoScan.FindSomeThings.main import frame
from cve.WebInfoScan.FindSomeThings.main import ask
from cve.WebInfoScan.FindSomeThings.main import Update
from cve.WebInfoScan.FindSomeThings.main import output
from libs.outprint import OutPrintInfo,OutPrintInfoErr
from rich.prompt import Prompt
#命令行参数
class Find_Some_Thing:
    # def parse_args():
    #     parser = argparse.ArgumentParser()
    #     parser.add_argument('-u', '--url', dest='url', help='Target Url')
    #     parser.add_argument('-f', '--file', dest='file', help='Target Url File', type=argparse.FileType('r'))
    #     parser.add_argument('-m', '--middleware', dest='middleware', help='Target middleware',action='store_true')
    #     parser.add_argument('-p', '--poc', dest='poc', help='Proof of concept',action='store_true')
    #     parser.add_argument('-o', '--outputurl', dest='outputurl', help='Output file name')
    #     parser.add_argument('-i', '--install', dest='install', help='finger install',action='store_true')
    #     parser.add_argument('-up', '--update', dest='update', help='Update the yaml file',action='store_true')
    #     return parser.parse_args()
    #

    #程序入口点
    def main(self,target):
        output.title()
        # args = parse_args()
        # if args.file:
        #     file=args.file
        #     if not args.middleware and not args.poc:
        #         frame.check_frame(file).fileDeal()
        #         file=deal.Deal(file).fileDeal()
        #     elif args.middleware:
        #         frame.check_frame(file).fileDeal()
        #     elif args.poc:
        #         file=deal.Deal(file).fileDeal()


        url=target["url"].strip('/ ')
        OutPrintInfo("[b bright_cyan]1[/b bright_cyan]","通过指定url进行指纹识别和脆弱点搜索")
        OutPrintInfo("[b bright_cyan]2[/b bright_cyan]","指纹识别")
        OutPrintInfo("[b bright_cyan]3[/b bright_cyan]","脆弱点搜索")
        OutPrintInfo("[b bright_cyan]4[/b bright_cyan]","更新yaml 跟新规则库中的yaml文件")
        OutPrintInfo("[b bright_cyan]5[/b bright_cyan]","安装和更新指纹库")
        choose = int(Prompt.ask("[b bright_red]输入对应功能选项"))
        if choose == 1:
        # if not args.middleware and not args.poc:
            frame.API2(url)
            target=deal.Deal(url).RequestHeadDeal()
            ask.Request(target)
        elif choose == 2:
        # elif args.middleware:
            frame.API2(url)
        elif choose == 3:
        # elif args.poc:
            target=deal.Deal(url).RequestHeadDeal()
            ask.Request(target)
        #
        #
        elif choose == 4:
        # if args.install:
            frame.install()
        elif choose == 5:
        # if args.update:
            Update.CheckEnv()
        else:
            OutPrintInfoErr("请检测输入......")