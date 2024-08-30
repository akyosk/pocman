#!/user/bin/env python3
# -*- coding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr
def LoadSqlmap(url):
    import os
    try:
        dir = os.getcwd()
        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u {url} --output-dir={dir}/result/ --batch --risk 3 --threads=10 --random-agent --ignore-code=555')
        os.system(f"sqlmap -u \"{url}\" --output-dir={dir}/result/ --batch --risk 3 --threads=10 --random-agent --ignore-code=555")
    except Exception as e:
        OutPrintInfoErr(e)