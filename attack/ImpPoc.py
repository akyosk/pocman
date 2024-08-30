#!/user/bin/env python3
# -*- coding: utf-8 -*-
from cve.Shiro.Shiro_Exploit import Shiro_Exp_Scan
from cve.Shiro.Shiro_File_Dump import Shiro_File_Dump_Scan

def Shiro_Poc(target,progress):
    _poc_list=[Shiro_File_Dump_Scan,Shiro_Exp_Scan]
    try:
        tasks = progress.add_task("[green]Subtask", total=len(_poc_list))
        for poc in _poc_list:
            poc().main(target)
            progress.update(tasks, advance=1)
    except Exception:
        pass
