#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from pub.com.outprint import OutPrintInfoErr
class WPvSCAN_Scan:
    def main(self,target):
        try:
            os.system(f"cd cve/Wordpress/WPvSCAN/;python wpvscan.py -t {target['url'].strip('/ ')}")
        except Exception as e:
            OutPrintInfoErr(e)