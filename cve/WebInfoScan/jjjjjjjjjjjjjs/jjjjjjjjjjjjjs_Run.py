#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from libs.outprint import OutPrintInfo
from rich.prompt import Prompt

class jjjjjjjjjjjjjs_Scan:
    def main(self,target):
        OutPrintInfo("Work", f"{'[b bright_red]~'*60}")
        OutPrintInfo("1", "爬取模式")
        OutPrintInfo("2", "fuzz模式 nobody")
        OutPrintInfo("3", "api模式 nofuzz")
        OutPrintInfo("4", "bypass模式 自动实施常见bypass")
        OutPrintInfo("5", "danger模式 解除危险接口限制")
        OutPrintInfo("6", "api模式 nobody header")
        OutPrintInfo("Work", f"{'[b bright_red]~' * 60}")

        choose = Prompt.ask("[b bright_cyan]输入需要执行的编号")
        try:
            if choose == "1":
                os.system(f"cd cve/WebInfoScan/jjjjjjjjjjjjjs/ && python jjjjjjjjjjjjjs.py {target['url'].strip('/ ')}")
            elif choose == "2":
                os.system(f"cd cve/WebInfoScan/jjjjjjjjjjjjjs/ && python jjjjjjjjjjjjjs.py {target['url'].strip('/ ')} fuzz nobody")
            elif choose == "3":
                ce = Prompt.ask("[b bright_cyan]是否指定API([b bred]y/n[/b bred])")
                if ce == 'y':
                    api = Prompt.ask("[b bright_cyan]输入指定API,如/jeecg-boot")
                    os.system(f"cd cve/WebInfoScan/jjjjjjjjjjjjjs/ && python jjjjjjjjjjjjjs.py {target['url'].strip('/ ')} api={api} nofuzz")
                os.system(f"cd cve/WebInfoScan/jjjjjjjjjjjjjs/ && python jjjjjjjjjjjjjs.py {target['url'].strip('/ ')} api nofuzz")

            elif choose == "4":
                os.system(f"cd cve/WebInfoScan/jjjjjjjjjjjjjs/ && python jjjjjjjjjjjjjs.py {target['url'].strip('/ ')} fuzz nobody bypass")
            elif choose == "5":
                os.system(f"cd cve/WebInfoScan/jjjjjjjjjjjjjs/ && python jjjjjjjjjjjjjs.py {target['url'].strip('/ ')} fuzz nobody danger")
            elif choose == "6":
                hd = Prompt.ask("[b bright_cyan]输入header")
                os.system(f"cd cve/WebInfoScan/jjjjjjjjjjjjjs/ && python jjjjjjjjjjjjjs.py {target['url'].strip('/ ')} api nobody header={hd}")
            else:
                OutPrintInfo("jjjjjjjjjjjjjs","检测输入")
                return
        except Exception:
            pass
