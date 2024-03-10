#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
class NacosR:
    def main(self,target):
        url = target["url"].strip('/ ')
        os.system(f"cd cve/Nacos/HKEcho_Nacos_main && python HKEcho_Nacos.py -u {url}")