#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import json
import re
import requests
from pub.com.outprint import OutPrintInfo
import urllib3
from pub.com.loadyamlset import ConfigLoader
api_list = ConfigLoader().get_values()["api-list"]
urllib3.disable_warnings()
class HistoryIpScan:
    def __init__(self):
        self._api_list = api_list
    def _domains_scan(self, domain, api_key):
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        head = {"APIKEY": api_key, "accept": "application/json"}
        res = requests.get(url, headers=head)
        res_json = json.loads(res.text)
        if "You've exceeded the usage limits for your account." in res.text:
            return "You've exceeded the usage limits for your account."
        if res_json['subdomains']:
            domain_list = res_json["subdomains"]
            return domain_list
        else:
            return "None"

    def _Ips_And_Dns(self, domain, api_key):
        ips_list = []
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        headers = {
            "accept": "application/json",
            "APIKEY": api_key
        }
        # print(headers)
        try:
            response = requests.get(url, headers=headers)
            if "You've exceeded the usage limits for your account." in response.text:
                OutPrintInfo("Securitytrails", "[b bright_yellow]Securitytrails-Key没有查询次数 :(")
                return "You've exceeded the usage limits for your account."
            json_bytes = json.loads(response.text)
            if json_bytes['records']:
                records = json_bytes['records']

                for j in records:
                    for res in j['values']:
                        res_dns = f"IP[[b bright_red]{res['ip']}[/b bright_red]] 第一次出现[b bright_red]{j['first_seen']}[/b bright_red] 最后一次出现[b bright_red]{j['last_seen']}[/b bright_red] 服务信息[b bright_red]{j['organizations']}[/b bright_red]"
                        if res_dns not in ips_list:
                            ips_list.append(res_dns)
                return ips_list
            else:
                OutPrintInfo("Securitytrails", "[b bright_yellow]Securitytrails没有匹配到IP相关结果 :(")
                return "None"
        except Exception:
            OutPrintInfo("Securitytrails", "[b bright_yellow]连接Securitytrails-Key出错 :(")




    def _api_scan_work(self, api_key):
        try:
            res_domain = self._url
            domains = self._domains_scan(res_domain, api_key)

            # 历史ip和dns
            ips = self._Ips_And_Dns(res_domain, api_key)
            if ips:
                if ips == "You've exceeded the usage limits for your account.":
                    OutPrintInfo("IP", "[b blue]接口免费查询数量已经全部使用")
                    return "You've exceeded the usage limits for your account."
                if ips == "None":
                    return "None"
                OutPrintInfo("IP","[b blue]找到历史IP[/b blue]")
                for i in ips:
                    OutPrintInfo("IP",i)
            if domains:
                if domains == "None":
                    return "None"
                if domains == "You've exceeded the usage limits for your account.":
                    OutPrintInfo("SubDomain", "[b blue]接口免费查询数量已经全部使用")
                    return "You've exceeded the usage limits for your account."
                domain_url = [res + '.' + res_domain for res in domains]
                OutPrintInfo("SUBDOMAIN",'[b blue]找到子域名[/b blue]')
                for i in domain_url:
                    OutPrintInfo("SUBDOMAIN",f"[b bright_red]{i}[/b bright_red]")

            OutPrintInfo("DNS/IP/DOMAIN",f"任务执行完成,找到[b bright_red]{len(domains)}[/b bright_red]个子域名,找到[b bright_red]{len(ips)}[/b bright_red]个IP.")
            return True
        except Exception as e:
            return False

    def _check(self):
        flag = False
        res = self._api_scan_work(self._api_list[0])
        if res:
            if res == "You've exceeded the usage limits for your account.":
                return False
            if res == "None":
                return False
            flag = True
        else:
            num = 1
            for i in self._api_list[1:]:
                res_twice = self._api_scan_work(i)
                if res_twice:
                    flag = True
                    break
                else:
                    OutPrintInfo("WEB-API",f"目前有[b bright_red]{num}[/b bright_red]个接口免费数量已经全部使用，剩余[b bright_red]{len(self._api_list) - num}[/b bright_red]个接口待测")
                    num += 1
                    if num == len(self._api_list):
                        flag = False
        if flag:
            return True
        else:
            return False

    def main(self,target):
        self._url = target["domain"].strip('/ ')
        if '://' in self._url:
            domain = self._url.split('/')[2]
        else:
            domain = self._url
        pattern = r'[a-zA-Z]'
        data_check = bool(re.search(pattern, domain))
        if data_check:
            OutPrintInfo("SUBDOMAIN","开始通过接口查找子域名......")
            OutPrintInfo("SUBDOMAIN","需开启[b bright_red]VPN[/b bright_red]")
            res = self._check()
            if res:
                OutPrintInfo("SUBDOMAIN","接口信息查询结束")
            else:
                OutPrintInfo("Securitytrails","[b cyan]接口免费查询数量已经全部使用,请更换接口 :(")
        else:
            OutPrintInfo("SUBDOMAIN","目标不具备子域名搜索条件")
