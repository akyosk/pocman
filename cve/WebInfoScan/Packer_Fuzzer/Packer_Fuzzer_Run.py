#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
from libs.outprint import OutPrintInfoErr,OutPrintInfo
class Packer_Fuzzer_Run_Scan:
    def main(self,target):
        url = target["url"].strip('/ ')
        proxy = target["proxy"]
        if proxy:
            if "://" in proxy:
                try:
                    os.system(f"cd ./cve/WebInfoScan/Packer_Fuzzer/ && python PackerFuzzer.py -u {url} -l zh -t adv -p {proxy}")
                    OutPrintInfo("Packer-Fuzzer", "结果保存于/cve/WebInfoScan/Packer_Fuzzer/reports")
                except Exception as e:
                    OutPrintInfoErr(e)
            else:
                OutPrintInfo("Packer-Fuzzer","代理需要服务头")
                return
        else:
            try:
                os.system(f"cd ./cve/WebInfoScan/Packer_Fuzzer/ && python PackerFuzzer.py -u {url} -l zh -t adv")
            except Exception as e:
                OutPrintInfoErr(e)