#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from pub.com.outprint import OutPrintInfoErr,OutPrintInfo
class SqlMap_Run_Scan:
    def main(self,target):
        q = target["sqlmap"]
        dir = os.getcwd()
        if "-r " in q:
            qs = q.split("-r ")[-1]
            q = "-r " +dir +"/"+qs
        if '-u "' not in q and "-r " not in q:
            OutPrintInfo("SqlMap","[b yellow]url需要引号包含")
            return
        try:
            OutPrintInfo("SqlMap",f"[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap {q} --output-dir={dir}/result/ --batch")
            os.system(f"sqlmap {q} --output-dir={dir}/result/ --batch")
        except Exception as e:
            OutPrintInfoErr(e)