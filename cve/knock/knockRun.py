#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
class Knock:
    def main(self,target):
        domain = target["domain"].strip("/ ")
        threads = int(target['threads'])
        os.system(f"python cve/WebInfoScan/knock/knockpy.py {domain} -th {threads}")