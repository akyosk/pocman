import threading
import time
from cve.WebInfoScan.dirpro_main.script.backup import searchFiles
from cve.WebInfoScan.dirpro_main.script.rely import searchdir, proxies, ret
from libs.public.outprint import OutPrintInfo,OutPrintInfoErr
from libs.public.reqset import ReqSet
from rich.prompt import Prompt


def _start(target,rooturl):
    threads = int(target[1])
    proxy = target[2]
    req = ReqSet(proxy=proxy)
    proxies = req["proxy"]

    time_1 = time.time()
    sem = threading.Semaphore(threads)
    urlList = []
    urlList.extend(searchFiles(rooturl))
    #
    # if args.a:
    #     proxies['http'] = f"http://{args.a}"
    #     proxies['https'] = f"http://{args.a}"
    OutPrintInfo("[b red]1[/b red]","默认扫描,使用默认的top10000目录字典进行扫描")
    OutPrintInfo("[b red]2[/b red]","快速扫描备份文件和源码泄露文件")
    choose = Prompt.ask("[b red]输入对应编号进行扫描")
    if choose == "2":
        sem = threading.Semaphore(5)
        searchdir(urlList,sem,rooturl,proxies)

    elif choose == "1":
        defaultword = './cve/WebInfoScan/dirpro_main/wordlist/default'
        f = open(defaultword, 'r')
        files = f.read().splitlines()
        for file in files:
            urlList.append(f'{rooturl}/{file}')
        f.close()
        searchdir(urlList,sem,rooturl,proxies)
    else:
        OutPrintInfoErr("检测输入编号是否错误")
        return
    return (time_1,ret)