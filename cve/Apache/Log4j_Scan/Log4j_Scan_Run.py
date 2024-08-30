#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from pub.com.outprint import OutPrintInfoErr,OutPrintInfo
class Log4j_Scan_Scan:
    def main(self,target):
        q = target["url"]
        try:
            os.system(f"cd cve/Apache/Log4j_Scan && python log4j-scan.py -u {q} --run-all-tests")
        except Exception as e:
            OutPrintInfoErr(e)