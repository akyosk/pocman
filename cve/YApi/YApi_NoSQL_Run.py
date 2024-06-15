#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from pub.com.outprint import OutPrintInfoErr
class YApi_NoSQL_Scan:
    def main(self,target):
        url = target["url"].strip('/ ')
        try:
            os.system(f"cd cve/YApi/ && python YApi_NoSQL.py --debug one4all -u {url}")
        except Exception as e:
            OutPrintInfoErr(e)