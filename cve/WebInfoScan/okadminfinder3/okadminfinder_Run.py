#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from libs.outprint import OutPrintInfoErr,OutPrintInfo
class okadminfinder_Run_Scan:
    def main(self,target):
        url = target["url"].strip('/ ')
        try:
            os.system(f"cd ./cve/WebInfoScan/okadminfinder3/ && python okadminfinder.py -u {url} -r")
        except Exception as e:
            OutPrintInfoErr(e)