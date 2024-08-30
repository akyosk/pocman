#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr


class CensysDomainInfo:
    def main(self,target):
        domain = target["domain"].strip()
        cookie = target["cookie"]
        if '://' in target['domain']:
            domain = target["domain"].split('://')[-1].strip('/ ')
        if not cookie:
            OutPrintInfoErr("必须含有cookie值")
            return

        url = f'https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names%3A+{domain}&per_page=100&virtual_hosts=EXCLUDE'
        header = {
            'accept': 'application/json',
            'Authorization': cookie
        }
        response = requests.get(url,headers=header).json()
        lis = response['result']['hits']

        for i in lis:
            port_list = []
            OutPrintInfo("Censys",f'IP [b bright_red]{i["ip"]}')
            # print(f'>>> IP: {i["ip"]}')
            for b in i['services']:
                port_list.append(str(b['port']))
            ports = ' '.join(port_list)
            OutPrintInfo("Censys", f'PORTS [b bright_red]{ports}')
            # print(f'>>> PORTS: {ports}')
            OutPrintInfo("Censys", f'{"~"*50}')
# CensysDomain().config(['bit.ly'])