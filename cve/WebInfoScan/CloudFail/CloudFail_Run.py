#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from libs.outprint import OutPrintInfoErr

class CloudFail_Run_Scan:
    def main(self,target):
        domain = target['url'].strip('/ ')
        try:
            os.system(f"cd cve/WebInfoScan/CloudFail/ && python cloudfail.py --target {domain.split('://')[-1]}")
        except Exception as e:
            OutPrintInfoErr(e)