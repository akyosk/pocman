#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from pub.com.outprint import OutPrintInfoErr,OutPrintInfo
class CloakQuest3r_Run_Scan:
    def main(self,target):
        url = target["url"].strip('/ ')
        try:
            os.system(f"cd ./cve/WebInfoScan/CloakQuest3r/ && python CloakQuest3r.py {url}")
        except Exception as e:
            OutPrintInfoErr(e)