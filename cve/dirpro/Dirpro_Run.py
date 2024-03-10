#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from libs.outprint import OutPrintInfoErr

class Dirpro_Scan:
    def main(self,target):
        proxy = None
        if target['proxy']:
            if "://" in target['proxy']:
                proxy = target["proxy"].split("://")[-1]

            else:
                proxy = f"http://{target['proxy']}"
        try:
            os.system(f"cd cve/WebInfoScan/dirpro/;python dirpro.py -u {target['url'].strip('/ ')} -t {int(target['threads'])} -a {proxy}")

        except Exception as e:
            OutPrintInfoErr(e)
