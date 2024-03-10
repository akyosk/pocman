#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from libs.outprint import OutPrintInfoErr
class VulnX_Scan:
    def main(self,target):
        try:
            os.system(f"cd cve/VulsScan/VulnX && python vulnx.py -u {target['url'].strip('/ ')}")
        except Exception as e:
            OutPrintInfoErr(e)