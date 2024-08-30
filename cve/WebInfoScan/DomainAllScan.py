import time
from bs4 import BeautifulSoup
import re
import feedparser
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
import dns.resolver
import json
import base64
import requests
from urllib.parse import quote
from urllib.parse import urlparse
from pub.com.outprint import OutPrintInfo
from datetime import datetime
import urllib3
import mmh3
from rich.progress import Progress

urllib3.disable_warnings()


def get_set():
    from pub.com.loadyamlset import ConfigLoader
    return ConfigLoader().get_values()


config_yaml_values = get_set()
api_list = config_yaml_values['api-list']
censys_auth = config_yaml_values['censys_auth']
shodan_api = config_yaml_values['shodan-api']
virustotal_api = config_yaml_values['virustotal-api']
dnsdump_csrftoken = config_yaml_values['dnsdump-csrftoken']
fofa_email = config_yaml_values['fofa_email']
fofa_key = config_yaml_values['fofa_key']
yt_key = config_yaml_values['yt-key']
viewdns_key = config_yaml_values['viewdns-key']
fullhunt_api = config_yaml_values['fullhunt-api']
zoomeye_key = config_yaml_values['zoomeye-key']
quake_key = config_yaml_values['quake-key']
binaryedge_key = config_yaml_values['binaryedge-key']
whoisxmlapi_key = config_yaml_values['whoisxmlapi-key']
hunter_how_key = config_yaml_values['hunter-how-key']
daydaymap_key = config_yaml_values['daydaymap-key']



class CERTScan:
    def get_rss_for_domain(self, domain):
        # print(domain)
        """Pull the domain identity information from CERT.sh"""
        OutPrintInfo("CERT", f"Retrieving information about [b bright_red]{domain}[/b bright_red] from CERT.sh...")
        results_raw = requests.get(self.base_url.format(domain)).content
        results_entries = feedparser.parse(results_raw)["entries"]
        OutPrintInfo("CERT", "Retrieval of info done.")
        return results_entries

    def parse_entries(self, identity, results_list):
        entries_raw = None
        """This is pretty gross, but necessary when using CERT.sh: parse the contents of the summary
        entry and return individual host names."""
        line_breaks = ["<br>", "<br />"]
        for cur_break in line_breaks:
            if cur_break in identity["summary"]:
                entries_raw = identity["summary"][:identity["summary"].index(cur_break)].replace("&nbsp;", "\n")
        entries = entries_raw.split("\n")
        for entry in entries:
            trimmed_entry = entry.strip()
            stringified_entry = str(trimmed_entry)
            results_list.append(stringified_entry)

    def format_entries(self, results, do_resolve_dns):
        final_results = None
        """Sort and deduplicate hostnames and, if DNS resolution is turned on, resolve hostname"""
        sorted_results = sorted(set(results))
        if do_resolve_dns:
            try:
                OutPrintInfo("CERT", "DNS resolution turned on.")
                final_results = []
                for cur_result in sorted_results:
                    if "*" not in cur_result:
                        OutPrintInfo("CERT", f"Resolving {cur_result}...")
                        try:
                            ip_addresses = dns.resolver.query(cur_result)
                            for ip_address in ip_addresses:
                                final_results.append("{}\t{}".format(cur_result, ip_address))
                        except dns.resolver.NoAnswer:
                            final_results.append(cur_result)
                        OutPrintInfo("CERT", "... done.")
                    else:
                        final_results.append(cur_result)
            except Exception as e:
                OutPrintInfo("CERT", "[b yellow]未能从CERT搜索到目标信息或者连接出错")
        else:
            final_results = sorted_results
        return final_results

    def main(self, target):
        self.base_url = "https://crt.sh/atom?q=%25.{}"
        resolve_dns = False
        domains = target
        if "://" in domains:
            domains = domains.split("://")[-1]
        results = []
        # for cur_domain in domains:
        domain = domains.strip()
        results_entries = self.get_rss_for_domain(domain)
        for cur_entry in results_entries:
            self.parse_entries(cur_entry, results)
        final_results = self.format_entries(results, resolve_dns)
        if final_results:
            OutPrintInfo("CERT", f"通过证书共找到 [b bright_red]{str(len(final_results))}[/b bright_red] 个子域名")
            return final_results
        else:
            OutPrintInfo("CERT", f"通过证书未能找到相关结果 :(")
            return None


class SecuritytrailsScan:
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

    def _api_scan_work(self, api_key):
        try:
            res_domain = self._url
            domains = self._domains_scan(res_domain, api_key)
            if domains:
                if domains == "You've exceeded the usage limits for your account.":
                    # OutPrintInfo("Securitytrails", "[b bright_red]Securitytrails接口已没有查询数量使用,需要更换Key :(")
                    return "You've exceeded the usage limits for your account."
                if domains == "None":
                    return "None"
                else:
                    domain_url = [res + '.' + res_domain for res in domains]
                    OutPrintInfo("Securitytrails",
                                 f"任务执行完成Securitytrails共找到 [b bright_red]{len(domains)}[/b bright_red] 个子域名")
                    return domain_url
            else:
                # OutPrintInfo("Securitytrails", "[b yellow]未能在Securitytrails匹配到相关结果 :(")
                return False
        except Exception as e:
            # OutPrintInfo("Securitytrails", "[b yellow]无法连接Securitytrails或者没有匹配到相关结果 :(")
            return False

    def _check(self):
        # domainRes = None
        res = self._api_scan_work(self._api_list[0])

        if res == "You've exceeded the usage limits for your account.":
            OutPrintInfo("Securitytrails", "[b yellow]Securitytrails接口查询数量用尽")
            OutPrintInfo("Securitytrails", "[b bright_cyan]开始遍历Securitytrails-Api列表...")
            num = 1
            for i in self._api_list[1:]:
                res_twice = self._api_scan_work(i)
                if res_twice:
                    return res_twice
                else:
                    OutPrintInfo("WEB-API",
                                 f"目前有[b bright_red]{num}[/b bright_red]个接口免费数量已经全部使用，剩余[b bright_red]{len(self._api_list) - num}[/b bright_red]个接口待测")
                    num += 1

            return False
        elif res == "None":
            return False
        else:
            return res

    def main(self, target):
        self._url = target
        if self._url:
            OutPrintInfo("Securitytrails", "开始通过Securitytrails接口查找子域名......")
            res = self._check()
            if res:
                # OutPrintInfo("Securitytrails","使用Securitytrails接口信息查询结束")
                return res
            else:
                OutPrintInfo("Securitytrails", "[b yellow]使用Securitytrails没有获取到域名相关结果 :(")
                return None
        else:
            OutPrintInfo("Securitytrails", "[b yellow]目标不具备子域名搜索条件 :(")
            return None


class SecuritytrailsIPScan:
    def __init__(self):
        self._api_list = api_list

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
                OutPrintInfo("Securitytrails", "[b yellow]Securitytrails-Key没有查询次数 :(")
                return "You've exceeded the usage limits for your account."

            json_bytes = json.loads(response.text)
            records = json_bytes['records']
            if json_bytes['records']:
                for j in records:
                    for res in j['values']:
                        res_dns = res['ip']
                        if res_dns not in ips_list:
                            ips_list.append(res_dns)
                OutPrintInfo("Securitytrails",
                             f"任务执行完成Securitytrails共找到 [b bright_red]{str(len(ips_list))}[/b bright_red] 个IP")
                return ips_list
            else:
                # OutPrintInfo("Securitytrails", "[b yellow]Securitytrails没有匹配到IP相关结果 :(")
                return "None"
        except Exception:
            # OutPrintInfo("Securitytrails", "[b yellow]无法连接Securitytrails或者没有匹配到IP相关结果 :(")
            return False

    def _api_scan_work(self, api_key):
        try:
            res_domain = self._url
            # 历史ip和dns
            ips = self._Ips_And_Dns(res_domain, api_key)

            if ips:
                if ips == "None":
                    return "None"
                elif ips == "You've exceeded the usage limits for your account.":
                    return "You've exceeded the usage limits for your account."
                return ips
            return False
        except Exception as e:
            # OutPrintInfo("Securitytrails", "[b yellow]无法连接Securitytrails或者没有匹配到IP相关结果 :(")
            return False

    def _check(self):
        res = self._api_scan_work(self._api_list[0])

        if res == "None":
            return False
        elif res == "You've exceeded the usage limits for your account.":
            OutPrintInfo("Securitytrails", "[b bright_cyan]开始遍历Securitytrails-Api列表...")
            num = 1
            for i in self._api_list[1:]:
                res_twice = self._api_scan_work(i)
                if res_twice:
                    return res_twice
                else:
                    OutPrintInfo("Securitytrails",
                                 f"目前有[b bright_red]{num}[/b bright_red]个接口免费数量已经全部使用，剩余[b bright_red]{len(self._api_list) - num}[/b bright_red]个接口待测")
                    num += 1

            return False
        else:
            return res

    def main(self, target):
        self._url = target
        if '://' in self._url:
            domain = self._url.split('://')[-1]
        else:
            domain = self._url
        pattern = r'[a-zA-Z]'
        data_check = bool(re.search(pattern, domain))
        if data_check:
            OutPrintInfo("Securitytrails", "开始通过接口查找历史IP......")
            res = self._check()
            if res:
                # OutPrintInfo("Securitytrails", "使用Securitytrails接口信息查询结束")
                return res
            else:
                OutPrintInfo("Securitytrails", "[b yellow]使用Securitytrails没有获取到IP相关结果 :(")
                return None
        else:
            OutPrintInfo("Securitytrails", "[b yellow]目标不具备子域名搜索条件 :(")
            return None


class Shodan:
    def main(self, domain):
        # <- here your API KEY
        if not shodan_api:
            OutPrintInfo("YT", "[b cyan]未检测到Shodan-Key,不执行Shodan相关操作")
            return None
        apikey = shodan_api
        url = "https://api.shodan.io/dns/domain/{domain}?key={apikey}".format(domain=domain, apikey=apikey)
        try:
            resp = requests.get(url, timeout=5).text

            resp = json.loads(resp)


            result = []
            for item in resp['data']:
                subdomain = item['subdomain']
                if subdomain not in result:
                    result.append(subdomain + "." + domain)
            OutPrintInfo("Shodan", f"任务执行完成Shodan共找到 [b bright_red]{str(len(result))}[/b bright_red] 个子域名")
            return result
        except Exception:
            OutPrintInfo("Shodan", "[b yellow]请求Shodan查询时出错 :(")
            return None


class CensysDomainInfo:
    def main(self, target):
        domain = target
        cookie = censys_auth
        if '://' in target:
            domain = target.split('://')[-1]
        if not cookie:
            OutPrintInfo("Censys", "未检测到Censys-Token")
            return None
        ip_list = []
        url = f'https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names%3A+{domain}&per_page=100&virtual_hosts=EXCLUDE'
        header = {
            'accept': 'application/json',
            'Authorization': cookie
        }
        try:
            response = requests.get(url, headers=header).json()
            lis = response['result']['hits']

            for i in lis:
                if i not in ip_list:
                    ip_list.append(i["ip"])
            if ip_list:
                OutPrintInfo("Censys",
                             f"任务执行完成Censys共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return ip_list
        except Exception:
            OutPrintInfo("Censys", "[b yellow]请求Censys查询时出错 :(")
            return None


class Work:
    def fofa(self, ip):
        res = FofaIp().main(ip)
        return res if res else None

    def vt(self, ip):
        res = VirustotalIP().main(ip)
        return res if res else None

    def sec(self, ip):
        domain_list = []
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        }
        url = f"https://securitytrails.com/_next/data/1e8b4b75/list/ip/{ip}.json?ip={ip}"
        try:
            res = requests.get(url, headers=header)
            res2 = json.loads(res.text)

            for i in res2['pageProps']['serverResponse']['data']['records']:
                if i['hostname'] not in domain_list:
                    domain_list.append(i['hostname'])
            if domain_list:
                return domain_list
            else:
                return None
        except Exception:
            return None
            pass

    def yt(self, ip):
        res = YtIp().main(ip)
        return res if res else None

    def quake(self, ip):
        res = Quake_IP().main(ip)
        return res if res else None

    def main(self, ip):
        domain_list = []
        res1 = self.sec(ip)
        res2 = self.vt(ip)
        res3 = self.fofa(ip)
        res4 = self.yt(ip)
        res5 = self.quake(ip)
        if res1:
            for i in res1:
                if i not in domain_list:
                    domain_list.append(i)
        if res2:
            for i in res2:
                if i not in domain_list:
                    domain_list.append(i)
        if res3:
            for i in res3:
                if i not in domain_list:
                    domain_list.append(i)
        if res4:
            for i in res4:
                if i not in domain_list:
                    domain_list.append(i)
        if res5:
            for i in res5:
                if i not in domain_list:
                    domain_list.append(i)
        return domain_list if domain_list else None


class Virustotal:
    def main(self, domian):
        domain_list = []
        url = f"https://www.virustotal.com/api/v3/domains/{domian}/relationships/subdomains?limit=100"
        if not virustotal_api:
            OutPrintInfo("Virustotal", "[b cyan]未检测到Virustotal-Api-Key,不执行Virustotal相关操作")
            return None
        headers = {
            "accept": "application/json",
            "x-apikey": virustotal_api
        }
        try:
            response = requests.get(url, headers=headers)

            resq = json.loads(response.text)
            for i in resq['data']:
                domain_list.append(i['id'])
            if domain_list:
                OutPrintInfo("Virustotal",
                             f"任务执行完成Virustotal共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            else:
                OutPrintInfo("Virustotal", "[b yellow]Virustotal未搜索到相关结果 :(")
            return domain_list if domain_list else None
        except Exception:
            OutPrintInfo("Virustotal", "[b yellow]请求Virustotal查询时出错 :(")
            return None


class VirustotalIP:
    def main(self, ip):
        if not virustotal_api:
            # OutPrintInfo("Virustotal","[b cyan]未检测到Virustotal-Api-Key,不执行Virustotal相关操作")
            return None
        domain_list = []
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/relationships/resolutions?limit=10"

        headers = {
            "accept": "application/json",
            "x-apikey": virustotal_api
        }
        try:
            response = requests.get(url, headers=headers)
            resq = json.loads(response.text)
            for i in resq['data']:
                domain_list.append(i['id'].replace(ip, ''))

            return domain_list if domain_list else None
        except Exception:
            return None


class DnsDumpster:
    def main(self, domain):
        if not dnsdump_csrftoken:
            OutPrintInfo("DnsDumpster", "[b cyan]未检测到Dnsdump-csrftoken,不执行Dnsdump-csrftoken相关操作")
            return None, None
        ip_list = []
        domain_list = []
        url = "https://dnsdumpster.com/"
        header = {
            "Host": "dnsdumpster.com",
            "Cookie": f"csrftoken={dnsdump_csrftoken};",
            "Content-Length": "119",
            "Cache-Control": "max-age=0",
            'Sec-Ch-Ua': '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
            "Origin": "https://dnsdumpster.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Dest": "document",
            "Referer": "https://dnsdumpster.com/",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        }
        data = f"csrfmiddlewaretoken={dnsdump_csrftoken}&targetip={domain}&user=free"
        try:
            reqs = requests.post(url, headers=header, data=data)
            pattern = r'href="https://api\.hackertarget\.com/httpheaders/\?q=(.*?)"'
            pattern2 = r'href="https://api\.hackertarget\.com/reverseiplookup/\?q=(.*?)"'
            match = re.findall(pattern, reqs.text)
            ip_match = re.findall(pattern2, reqs.text)

            if match:
                for i in match:
                    if '://' in i:
                        domain_list.append(i.split('://')[-1])

            if ip_match:
                for i in ip_match:
                    ip_list.append(i)
            OutPrintInfo("DnsDumpster",
                         f"任务执行完成DnsDumpster共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            OutPrintInfo("DnsDumpster",
                         f"任务执行完成DnsDumpster共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")

            return ip_list, domain_list
        except Exception:
            OutPrintInfo("DnsDumpster", "[b yellow]请求DnsDumpster查询时出错 :(")
            return None, None


class Fofa:
    def main(self, domain):
        if not fofa_key:
            OutPrintInfo("Fofa", "[b cyan]未检测到Fofa-Key,不执行Fofa相关操作")
            return None, None
        ip_list = []
        domain_list = []
        query = f'domain="{domain}"'
        base64_str = base64.b64encode(query.encode('utf-8')).decode()
        query_str = quote(base64_str)
        # print(query_str)

        url = f"https://fofa.info/api/v1/search/all?email={fofa_email}&key={fofa_key}&qbase64={query_str}&size=100&full=true"
        try:
            resq = requests.get(url)
            res_json = json.loads(resq.text)
            if res_json['error'] != True:
                for i in res_json['results']:
                    res_ip = i[1]
                    res_domain = i[0]
                    if res_ip not in ip_list:
                        if res_ip.split('.')[0] != '104' or res_ip.split('.')[0] != '172':
                            ip_list.append(res_ip)
                    if res_domain not in domain_list:
                        if "://" in res_domain:
                            pattern = r'[a-zA-Z]'
                            res_domain2 = res_domain.split("://")[-1]
                            res_check = bool(re.search(pattern, res_domain2))
                            if res_check:
                                domain_list.append(res_domain2)
                        else:
                            pattern = r'[a-zA-Z]'
                            res_check = bool(re.search(pattern, res_domain))
                            if res_check:
                                domain_list.append(res_domain)
                OutPrintInfo("Fofa",
                             f"任务执行完成Fofa共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
                OutPrintInfo("Fofa",
                             f"任务执行完成Fofa共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return ip_list, domain_list
            else:
                if "F点余额不足" in resq.text:
                    OutPrintInfo("Fofa", "[b yellow]F点余额不足 :(")
                    return None, None
                OutPrintInfo("Fofa", "[b yellow]Fofa查询出错,检测Key是否可用 :(")
                return None, None
        except Exception:
            OutPrintInfo("Fofa", "[b yellow]请求Fofa查询时出错 :(")
            return None, None


class FofaIp:
    def main(self, ip):
        if not fofa_key:
            # OutPrintInfo("Fofa","[b cyan]未检测到Fofa-Key,不执行Fofa相关操作")
            return None
        domain_list = []
        query = f'ip="{ip}"'
        base64_str = base64.b64encode(query.encode('utf-8')).decode()
        query_str = quote(base64_str)

        url = f"https://fofa.info/api/v1/search/all?email={fofa_email}&key={fofa_key}&qbase64={query_str}&size=100&full=true"
        try:
            resq = requests.get(url)
            res_json = json.loads(resq.text)
            if res_json['error'] != True:
                for i in res_json['results']:
                    res_domain = i[0]

                    if res_domain not in domain_list:
                        if "://" in res_domain:
                            pattern = r'[a-zA-Z]'
                            res_domain2 = res_domain.split("://")[-1]
                            res_check = bool(re.search(pattern, res_domain2))
                            if res_check:
                                domain_list.append(res_domain2)
                        else:
                            pattern = r'[a-zA-Z]'
                            res_check = bool(re.search(pattern, res_domain))
                            if res_check:
                                domain_list.append(res_domain)

                return domain_list
            else:
                return None, None
        except Exception:
            # OutPrintInfo("DnsDumpster","[b yellow]Fofa未能获取到相关结果或无法连接 :(")
            return None, None


class Yt:
    def main(self, domain):
        search = f'domain="{domain}"'
        search = base64.urlsafe_b64encode(search.encode("utf-8")).decode()
        # print("search:", search)
        if not yt_key:
            OutPrintInfo("YT", "[b cyan]未检测到YT-Key,不执行YT相关操作")
            return None, None
        key = yt_key
        ip_list = []
        domain_list = []
        url = f"https://hunter.qianxin.com/openApi/search?api-key={key}&search={search}&page=1&page_size=100&is_web=3&start_time=2008-01-01&end_time=2023-11-18"
        try:
            resq = requests.get(url)
            res_json = json.loads(resq.text)

            if res_json['message'] == 'success':
                for i in res_json['data']['arr']:
                    if '无法查看' not in i['ip'] and '无法查看' not in i['domain']:
                        if i['ip']:
                            if i['ip'] not in ip_list:
                                ip_list.append(i['ip'])
                            # print(i['ip'])
                        if i['domain']:
                            if i['domain'] not in domain_list:
                                domain_list.append(i['domain'])
                OutPrintInfo("YT",
                             f"任务执行完成YT共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
                OutPrintInfo("YT", f"任务执行完成YT共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return ip_list, domain_list
            else:
                OutPrintInfo("YT", "[b yellow]使用YT未查询成功,检测Key是否可用 :(")
                return None, None
        except Exception:
            OutPrintInfo("YT", "[b yellow]请求YT查询时出错 :(")
            return None, None


class YtIp:
    def main(self, ip):
        search = f'ip="{ip}"'
        search = base64.urlsafe_b64encode(search.encode("utf-8")).decode()
        # print("search:", search)
        if not yt_key:
            # OutPrintInfo("YT","[b cyan]未检测到YT-Key,不执行YT相关操作")
            return None
        key = yt_key
        ip_list = []
        domain_list = []
        url = f"https://hunter.qianxin.com/openApi/search?api-key={key}&search={search}&page=1&page_size=100&is_web=3&start_time=2008-01-01&end_time=2023-11-18"
        try:
            resq = requests.get(url)
            res_json = json.loads(resq.text)

            if res_json['message'] == 'success':
                for i in res_json['data']['arr']:
                    if '无法查看' not in i['ip'] and '无法查看' not in i['domain']:
                        if i['domain']:
                            if i['domain'] not in domain_list:
                                domain_list.append(i['domain'])
                # OutPrintInfo("YT",f"任务执行完成YT共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
                # OutPrintInfo("YT",f"任务执行完成YT共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return domain_list
            else:
                # OutPrintInfo("YT", "[b yellow]使用YT未查询成功,检测Key是否可用 :(")
                return None
        except Exception:
            # OutPrintInfo("YT", "[b yellow]使用YT未查询成功,检测Key是否可用 :(")
            return None


class ViewDNS:
    def main(self, domain):
        url = f"https://api.viewdns.info/iphistory/?domain={domain}&apikey={viewdns_key}&output=json"
        ip_list = []
        if not viewdns_key:
            OutPrintInfo("ViewDNS", "[b cyan]未检测到ViewDNS-Key,不执行ViewDNS相关操作")
            return None
        try:
            req = requests.get(url)
            if 'Please select a different hostname and try again' in req.text:
                OutPrintInfo("ViewDNS", "[b yellow]使用ViewDNS未查询到相关结果 :(")
                return None
            res_json = json.loads(req.text)
            for i in res_json['response']['records']:
                if i['ip'] not in ip_list:
                    ip_list.append(i['ip'])
            OutPrintInfo("ViewDNS", f"任务执行完成ViewDNS共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
            return ip_list
        except Exception:
            OutPrintInfo("ViewDNS", "[b yellow]请求ViewDNS查询时出错 :(")
            return None


class Chaziyu:
    def main(self, domain):
        l = f"https://chaziyu.com/{domain}/"
        domain_list = []
        header = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
            # "Cookie": "Hm_lvt_7d51be3b7524d35798ad1304e725bd2c=1701340538; Hm_lpvt_7d51be3b7524d35798ad1304e725bd2c=1701340538"
        }
        try:
            r = requests.get(url=l, headers=header)
            soup = BeautifulSoup(r.text, "html.parser")
            j_link = soup.find_all('tr', class_='J_link')
            for i in j_link:
                link = i.find('a').text
                domain_list.append(link.strip())
            OutPrintInfo("Chaziyu",
                         f"任务执行完成Chaziyu共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            return domain_list
        except Exception:
            OutPrintInfo("Chaziyu", "[b yellow]请求Chaziyu查询时出错 :(")
            return None


class Jldc:
    def main(self, domain):
        l = f"https://jldc.me/anubis/subdomains/{domain}"
        domain_list = []
        header = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
        }
        try:
            r = requests.get(url=l, headers=header)
            s = json.loads(r.text)

            for i in s:
                domain_list.append(i.strip())
            if not domain_list:
                OutPrintInfo("Jldc", "[b yellow]Jldc未查询到子域相关结果 :(")
                return None
            OutPrintInfo("Jldc",
                         f"任务执行完成Jldc共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            return domain_list
        except Exception:
            OutPrintInfo("Jldc", "[b yellow]请求Jldc查询时出错 :(")
            return None


class Sitedossier:
    def main(self, domain):
        l = f"http://www.sitedossier.com/parentdomain/{domain}/"
        domain_list = []
        header = {
            "Host": "www.sitedossier.com",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Referer": "http://www.sitedossier.com/audit/?41336",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Connection": "close"
        }
        try:
            r = requests.get(url=l, headers=header)
            soup = BeautifulSoup(r.text, "html.parser")
            j_link = soup.find_all('li')
            for i in j_link:
                a_text = i.find('a').get_text(strip=True)
                req_domain = a_text.split("://")[-1].strip("/")
                domain_list.append(req_domain)
            OutPrintInfo("Sitedossier",
                         f"任务执行完成Sitedossier共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            return domain_list
        except Exception:
            OutPrintInfo("Sitedossier", "[b yellow]请求Sitedossier查询时出错 :(")
            return None


class Rapiddns:
    def main(self, domain):
        l = f"https://rapiddns.io/s/{domain}#result"
        header = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",

        }
        domain_list = []
        try:
            r = requests.get(url=l, headers=header)
            soup = BeautifulSoup(r.text, "html.parser")
            j_link = soup.find_all('th', {"scope": "row "})
            if not j_link:
                OutPrintInfo("Rapiddns", "[b yellow]Rapiddns未查询到子域相关结果 :(")
                return None
            for i in j_link:
                j = i.find_next('td').get_text(strip=True)
                domain_list.append(j.strip())
            if not domain_list:
                OutPrintInfo("Rapiddns", "[b yellow]Rapiddns未查询到子域相关结果 :(")
                return None
            OutPrintInfo("Rapiddns",
                         f"任务执行完成Rapiddns共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")

            return domain_list
        except Exception:
            OutPrintInfo("Rapiddns", "[b yellow]请求Rapiddns查询时出错 :(")
            return None


class Fullhunt:
    def main(self, domain):
        domain_list = []
        l = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        if not fullhunt_api:
            OutPrintInfo("Fullhunt", "[b cyan]未检测到Fullhunt-Key,不执行Fullhunt相关操作")
            return None
        header = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
            "X-API-KEY": fullhunt_api

        }
        try:
            r = requests.get(url=l, headers=header)
            if r.status_code == 404:
                OutPrintInfo("Rapiddns", "[b yellow]Fullhunt未查询到子域相关结果 :(")
                return None
            if r.status_code == 403:
                OutPrintInfo("Rapiddns", "[b yellow]Fullhunt没有查询积分 :(")
                return None
            s = json.loads(r.text)
            for i in s['hosts']:
                domain_list.append(i)
            OutPrintInfo("Fullhunt",
                         f"任务执行完成Fullhunt共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            return domain_list
        except Exception:
            OutPrintInfo("Fullhunt", "[b yellow]请求Fullhunt查询时出错 :(")
            return None


class Alienvault:
    def main(self, domain):
        l = f"https://otx.alienvault.com/otxapi/indicators/domain/passive_dns/{domain}"
        domain_list = []
        ip_list = []
        header = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
        }
        try:
            r = requests.get(url=l, headers=header)
            s = json.loads(r.text)
            for i in s['passive_dns']:
                if domain in i['hostname']:
                    domain_list.append(i['hostname'])

        except Exception:
            OutPrintInfo("Alienvault", "[b yellow]使用Alienvault查询DNS/Domain未成功,请求出错或未查询到数据")
        try:
            url = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns".format(domain=domain)
            resp = requests.get(url, timeout=5).text

            resp = json.loads(resp)

            for item in resp['passive_dns']:
                subdomain = item['hostname']
                if subdomain not in domain_list:
                    domain_list.append(subdomain)
        except Exception:
            OutPrintInfo("Alienvault", "[b yellow]请求Alienvault查询DNS/Domain时出错 :(")

        try:
            l = f"https://otx.alienvault.com/otxapi/indicators/domain/url_list/{domain}"
            header = {
                "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
            }

            r = requests.get(url=l, headers=header)
            s = json.loads(r.text)
            for i in s['url_list']:
                ip_list.append(i['result']['urlworker']['ip'])
                if i['hostname'] not in domain_list:
                    domain_list.append(i['hostname'])


        except Exception:
            OutPrintInfo("Alienvault", "[b yellow]请求Alienvault查询IP/Domain时出错 :(")
            return None, None
        OutPrintInfo("Alienvault",
                     f"任务执行完成Alienvault共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
        OutPrintInfo("Alienvault",
                     f"任务执行完成Alienvault共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")

        return ip_list, domain_list


class Certspotter:
    def main(self, domain):
        # certspotter -> LIST -> JSON: key -> dns_names
        url = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names".format(
            domain=domain)
        try:
            resp = requests.get(url, timeout=5).text

            resp = json.loads(resp)

            result = []
            for item in resp:
                for subdomain in item['dns_names']:
                    # too many dns names, filter for dns witch contains the domain
                    if domain in subdomain:
                        if subdomain not in result:
                            result.append(subdomain)
            OutPrintInfo("Certspotter",
                         f"任务执行完成Certspotter共找到 [b bright_red]{str(len(result))}[/b bright_red] 个子域名")
            return result
        except Exception:
            OutPrintInfo("Certspotter", "[b yellow]请求Certspotter查询时出错 :(")
            return None


class Hackertarget:
    def main(self, domain):
        i = f"https://api.hackertarget.com/hostsearch/?q=baidu.com"
        try:
            req = requests.get(i)
            if req.status_code == 200:
                res = req.text.split("\n")
                domain_list = []
                ip_list = []
                for i in res:
                    if i.split(',')[0] and i.split(',')[0] not in domain_list:
                        domain_list.append(i.split(',')[0])
                    if i.split(',')[-1] and i.split(',')[-1] not in ip_list:
                        ip_list.append(i.split(',')[-1])
                OutPrintInfo("Hackertarget",
                             f"任务执行完成Hackertarget共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名,{str(len(ip_list))}[/b bright_red] 个IP")
                return ip_list, domain_list
            else:
                OutPrintInfo("Hackertarget", "[b yellow]请求Hackertarget查询时出错 :(")
                return None, None
        except Exception:
            OutPrintInfo("Hackertarget", "[b yellow]请求Hackertarget查询时出错 :(")
            return None, None



class Archive:
    def main(self, domain):
        # webarchive -> TEXT URL LIST -> match subdomain
        url = "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey".format(
            domain=domain)
        try:
            resp = requests.get(url, timeout=5).text

            result = []
            pattern = "http(s)?:\/\/(.*\.%s)" % domain
            for item in resp.split('\n'):
                match = re.match(pattern, item)

                if match and re.match("^[a-zA-Z0-9-\.]*$", match.groups()[1]):
                    subdomain = match.groups()[1]
                    if subdomain not in result:
                        result.append(subdomain)

            OutPrintInfo("Archive",
                         f"任务执行完成Archive共找到 [b bright_red]{str(len(result))}[/b bright_red] 个子域名")
            return result

        except Exception:
            OutPrintInfo("Archive", "[b yellow]请求Archive查询时出错 :(")
            return None


class ZoomEye:
    def main(self, domain):
        url = f'https://api.zoomeye.org/domain/search?q={domain}&type=1&page=1'
        if not zoomeye_key:
            OutPrintInfo("ZoomEye", "[b cyan]未检测到ZoomEye-Key不执行相关操作")
            return None, None
        domain_list = []
        ip_list = []
        header = {
            "API-KEY": zoomeye_key,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Google/537.3"

        }
        try:
            re = requests.get(url, headers=header)
            s = json.loads(re.text)
            if s["status"] == 200:
                if s['list']:
                    for item in s['list']:
                        domain_list.append(item['name'])
                        if 'ip' in item and item['ip'] != []:
                            for i in item['ip']:
                                ip_list.append(i)
            OutPrintInfo("ZoomEye",
                         f"任务执行完成ZoomEye共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名,[b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
            return ip_list, domain_list
        except Exception:
            OutPrintInfo("ZoomEye", "[b yellow]请求ZoomEye查询IP/Domain时出错 :(")
            return None, None
class ZoomEyeHK:
    def main(self, domain):
        url = f"https://api.zoomeye.hk/domain/search?q={domain}&type=1&page=1"
        if not zoomeye_key:
            OutPrintInfo("ZoomEye", "[b cyan]未检测到HK-ZoomEye-Key不执行相关操作")
            return None
        header = {
            "API-KEY": zoomeye_key,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Google/537.3"
        }
        domain_list = []
        try:
            resp = requests.get(url, headers=header)
            json_str = json.loads(resp.text)
            if json_str["status"] == 200:
                for i in json_str["list"]:
                    domain_list.append(i["name"])
                OutPrintInfo("ZoomEye",
                             f"任务执行完成ZoomEye共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
                return domain_list
            elif json_str["status"] == 402:
                OutPrintInfo("ZoomEye", "[b yellow]请求ZoomEye积分不足")
                return None
            else:
                OutPrintInfo("ZoomEye", "[b yellow]请求ZoomEye出错")
                return None
        except Exception:
            OutPrintInfo("ZoomEye", "[b yellow]请求ZoomEye出错")
            return None

class Dnshistory:
    def main(self, domain):
        url = f"https://dnshistory.org/subdomains/1/{domain}"
        domain_list = []
        h = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        try:
            r = requests.get(url, headers=h)
            res = re.findall('<a href="/dns-records/(.*?)">', r.text)
            if res:
                for i in res:
                    domain_list.append(i.strip())
            else:
                OutPrintInfo("Dnshistory", f"[b yellow]使用Dnshistory查询未查询到相关子域名 :(")
            OutPrintInfo("Dnshistory",
                         f"任务执行完成Dnshistory共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            return domain_list
        except Exception as e:
            OutPrintInfo("Dnshistory", f"[b yellow]请求Dnshistory查询时出错 :(")
            return None


class Quake_Domain:
    def main(self, domain):
        domain_list = []
        ip_list = []
        if not quake_key:
            OutPrintInfo("Quake", "[b yellow]未检测到queke-key不执行相关操作 :(")
            return
        headers = {
            "X-QuakeToken": quake_key,
            "Content-Type": "application/json"
        }
        query_str = f'domain: "{domain}"'
        data = {
            "query": query_str,
            "start": 0,
            "size": 100,
            "ignore_cache": False,
            "latest": True,
            "shortcuts": [
                "610ce2adb1a2e3e1632e67b1"
            ],
        }
        try:
            response = requests.post(url="https://quake.360.net/api/v3/search/quake_service", headers=headers,
                                     json=data)
            if response.json()['message'] == "Successful.":
                for i in response.json()['data']:
                    if 'domain' in i or 'ip' in i:
                        if i['domain'] not in domain_list:
                            domain_list.append(i['domain'])
                        if i['ip'] not in ip_list:
                            ip_list.append(i['ip'])
                OutPrintInfo("Quake",
                             f"任务执行完成Quake共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名,[b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return domain_list, ip_list
            else:
                OutPrintInfo("Quake", f"[b yellow]使用Quake查询未成功,检测是否具有查询次数 :(")
                return None, None
        except Exception as e:
            OutPrintInfo("Quake", f"[b yellow]请求Quake查询时出错 :(")
            return None, None


class Quake_IP:
    def main(self, ip):
        domain_list = []
        if not quake_key:
            # OutPrintInfo("Quake","未检测到queke-key不执行相关操作")
            return None
        headers = {
            "X-QuakeToken": quake_key,
            "Content-Type": "application/json"
        }
        query_str = f'ip: "{ip}"'
        data = {
            "query": query_str,
            "start": 0,
            "size": 100,
            "ignore_cache": False,
            "latest": True,
            "shortcuts": [
                "610ce2adb1a2e3e1632e67b1"
            ],
        }
        try:
            response = requests.post(url="https://quake.360.net/api/v3/search/quake_service", headers=headers,
                                     json=data)
            if response.json()['message'] == "Successful.":
                for i in response.json()['data']:
                    if 'domain' in i:
                        domain_list.append(i['domain'])
                        # print(i['domain'])
                # OutPrintInfo("Quake",f"任务执行完成Quake共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
                return domain_list
            else:
                # OutPrintInfo("Quake", f"[b yellow]使用Quake查询未成功,检测是否具有查询次数 :(")
                return None
        except Exception as e:
            # OutPrintInfo("Quake",f"[b yellow]使用Quake查询未成功,{e} :(")
            return None


class Netlas:
    def main(self, domain):
        domain_list = []
        ip_list = []
        url = f'https://app.netlas.io/api/domains/?q=domain:(domain:*.{domain}+AND+NOT+domain:{domain})&start=0&indices='
        try:
            req = requests.get(url)
            json_req = req.json()
            if 'items' in json_req:
                for i in json_req['items']:
                    if 'domain' in i['data']:
                        if i['data']['domain'] not in domain_list:
                            domain_list.append(i['data']['domain'])
                    if 'a' in i['data']:
                        for j in i['data']['a']:
                            if j not in ip_list:
                                ip_list.append(j)
                OutPrintInfo("Netlas",
                             f"任务执行完成Netlas共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名,[b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return domain_list, ip_list
            else:
                OutPrintInfo("Netlas", f"[b yellow]使用Netlas查询未成功 :(")
                return None, None
        except Exception as e:
            OutPrintInfo("Netlas", f"[b yellow]请求Netlas查询时出错 :(")
            return None, None


class Binaryedge:
    def main(self, domain):
        domain_list = []
        url = f'https://api.binaryedge.io/v2/query/domains/subdomain/{domain}'
        if not binaryedge_key:
            OutPrintInfo("Binaryedge", "[b yellow]未检测到binaryedge-key不执行相关操作 :(")
            return None
        header = {"X-Key": binaryedge_key}
        try:
            req = requests.get(url, headers=header)
            json_req = req.json()
            if 'events' in json_req:
                for i in json_req['events']:
                    if i not in domain_list:
                        domain_list.append(i)
                OutPrintInfo("Binaryedge",
                             f"任务执行完成Binaryedge共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
                return domain_list
            else:
                OutPrintInfo("Binaryedge", f"[b yellow]使用Binaryedge查询未成功 :(")
                return None
        except Exception:
            OutPrintInfo("Binaryedge", f"[b yellow]请求Binaryedge查询时出错 :(")
            return None


class Google:
    def make_get_request(self, url):
        try:
            response = requests.get(url, verify=False, timeout=10)

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Print the content of the response (HTML content for a website)
                return response.text
            else:
                OutPrintInfo("Google", f"[b yellow]使用Google查询未成功 :(")
                # pass
                # print(f"Request failed with status code: {response.status_code}")

        except Exception as e:
            OutPrintInfo("Google", f"[b yellow]使用Google查询未成功 :(")
            # pass
            # print(f"An error occurred: {e}")

    def extract_urls(self, text):
        try:
            pattern = r'https?://\S+'  # This regex pattern matches URLs starting with "http://" or "https://" and followed by non-space characters.
            urls = re.findall(pattern, text)
            return urls
        except Exception:
            pass

    def remove_url_path(self, url):
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme
        netloc = parsed_url.netloc
        return f"{scheme}://{netloc}"

    def go(self, target_url):
        # Make the GET request to the website
        response = self.make_get_request(target_url)
        if not response:
            return ""
        urls = (self.extract_urls(response))
        results = []
        if urls:
            for url in urls:
                results.append(self.remove_url_path(url))
        return results

    def main(self, domain):
        # requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        pages = int(5)
        loops = 0
        results = pages * 10

        domains = []
        res_domain = []

        while loops < results:
            # Replace this URL with the website you want to access
            target_url = f"https://www.google.com/search?q=site:{domain}+-www&start={loops}"
            result_urls = self.go(target_url)
            if result_urls:
                domains.extend(list(filter(lambda link: "google" not in link, result_urls)))
            loops += 10

        if domains:
            unique_list = [x for i, x in enumerate(domains) if x not in domains[:i]]
            for item in unique_list:
                if item.split("://")[-1] not in res_domain:
                    res_domain.append(item.split("://")[-1])
        OutPrintInfo("Google", f"任务执行完成Google共找到 [b bright_red]{str(len(res_domain))}[/b bright_red] 个子域名")
        return res_domain


class Whoisxmlapi:
    def main(self, domain):
        if not whoisxmlapi_key:
            OutPrintInfo("Whoisxmlapi", "[b yellow]未检测到whoisxmlapi-Key不执行相关操作 :(")
            return None
        domain_list = []
        try:
            url = f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={whoisxmlapi_key}&domainName={domain}"
            req = requests.get(url)
            r = req.json()
            if req.status_code == 403:
                OutPrintInfo("Whoisxmlapi", "[b yellow]Whoisxmlapi-Key没有查询积分 :(")
                return None

            for i in r["result"]["records"]:
                domain_list.append(i["domain"])
            OutPrintInfo("Whoisxmlapi",
                         f"任务执行完成Whoisxmlapi共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            return domain_list
        except Exception:
            OutPrintInfo("Whoisxmlapi", "[b yellow]请求Whoisxmlapi查询时出错 :(")
            return None


class HunterHow:
    def main(self, domain):
        domain_list = []
        ip_list = []
        query = f'domain="{domain}"'
        encoded_query = base64.urlsafe_b64encode(query.encode("utf-8")).decode('ascii')
        if not hunter_how_key:
            OutPrintInfo("HunterHow", "[b yellow]未检测到hunter-how-Key不执行相关操作 :(")
            return None
        i = f"https://api.hunter.how/search?api-key={hunter_how_key}&query={encoded_query}&page=1&page_size=100&start_time=2024-01-01&end_time=2024-12-01"
        try:
            req = requests.get(i)
            if req.status_code == 200:
                json_str = json.loads(req.text)
                if json_str.get('code') == 200:
                    for res in json_str.get('data')['list']:
                        if res['domain'] not in domain_list:
                            domain_list.append(res['domain'])
                        if res['ip'] not in ip_list:
                            ip_list.append(res['ip'])
                    OutPrintInfo("HunterHow",
                                 f"任务执行完成HunterHow共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名,[b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                    return domain_list, ip_list

            OutPrintInfo("HunterHow", "[b yellow]请求HunterHow查询时出错 :(")
            return None,None
        except Exception:
            OutPrintInfo("HunterHow", "[b yellow]请求HunterHow查询时出错 :(")
            return None, None


class DayDayMap:
    def main(self, domain):
        domain_list, ip_list = [], []
        if not daydaymap_key:
            OutPrintInfo("DayDayMap", "[b yellow]未检测到DayDayMap-Key不执行相关操作 :(")
            return None
        headers = {
            'api-key': daydaymap_key
        }
        query = f'domain="{domain}"'
        encoded_query = base64.urlsafe_b64encode(query.encode("utf-8")).decode('ascii')
        data = {
            "page": 1,
            "page_size": 100,
            "keyword": encoded_query
        }
        try:
            response = requests.post('https://www.daydaymap.com/api/v1/raymap/search/all', headers=headers, json=data,
                                     verify=False)
            if response.status_code == 200:
                json_str = json.loads(response.text)
                if json_str.get('code') == 200:
                    for res in json_str.get('data')['list']:
                        if res['domain'] not in domain_list:
                            domain_list.append(res['domain'])
                        if res['ip'] not in ip_list:
                            ip_list.append(res['ip'])
                    OutPrintInfo("DayDayMap",
                                 f"任务执行完成DayDayMap共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名,[b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                    return domain_list, ip_list
            OutPrintInfo("DayDayMap", "[b yellow]请求DayDayMap查询时出错 :(")
            return None,None
        except Exception:
            OutPrintInfo("DayDayMap", "[b yellow]请求DayDayMap查询时出错 :(")
            return None, None

class C99NL:
    def main(self,search_domain):
        ip_list = []
        domain_list = []
        # 获取当前日期时间
        current_datetime = datetime.now()

        # 格式化日期时间为指定格式
        formatted_date = current_datetime.strftime('%Y-%m-%d')
        i = f"https://subdomainfinder.c99.nl/scans/{formatted_date}/{search_domain}"
        try:
            req = requests.get(i)
            if req.status_code == 200:
                reg = re.compile("<a class='link sd' target='_blank' rel='noreferrer' href='//(.*?)'>")
                reg_ip = re.compile("<a class='link ip' target='_blank' href='/geoip/(.*?)'>")
                matches = re.findall(reg, req.text)
                matches_ip = re.findall(reg_ip, req.text)
                for domain in matches:
                    if domain not in domain_list:
                        domain_list.append(domain.strip())

                for ip in matches_ip:
                    if ip not in ip_list:
                        ip_list.append(ip.strip())

                OutPrintInfo("C99NL",
                             f"任务执行完成C99NL共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名,[b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return domain_list, ip_list
            else:
                OutPrintInfo("C99NL", "[b yellow]请求C99NL查询时出错 :(")
                return None, None
        except Exception:
            OutPrintInfo("C99NL", "[b yellow]请求C99NL查询时出错 :(")
            return None, None


class JsFinderScan:
    def __init__(self):
        self._ssl = None
        self._threads = None
    def extract_URL(self,JS):
        pattern_raw = r"""
    	  (?:"|')                               # Start newline delimiter
    	  (
    	    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    	    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
    	    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    	    |
    	    ((?:/|\.\./|\./)                    # Start with /,../,./
    	    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
    	    [^"'><,;|()]{1,})                   # Rest of the characters can't be
    	    |
    	    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    	    [a-zA-Z0-9_\-/]{1,}                 # Resource name
    	    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    	    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    	    |
    	    ([a-zA-Z0-9_\-]{1,}                 # filename
    	    \.(?:php|asp|aspx|jsp|json|
    	         action|html|js|txt|xml)             # . + extension
    	    (?:\?[^"|']{0,}|))                  # ? mark with parameters
    	  )
    	  (?:"|')                               # End newline delimiter
    	"""
        pattern = re.compile(pattern_raw, re.VERBOSE)
        result = re.finditer(pattern, str(JS))
        if result == None:
            return None
        js_url = []
        return [match.group().strip('"').strip("'") for match in result
                if match.group() not in js_url]

    # Get the page source

    # Handling relative URLs
    def process_url(self,URL, re_URL):
        black_url = ["javascript:"]  # Add some keyword for filter url.
        URL_raw = urlparse(URL)
        ab_URL = URL_raw.netloc
        host_URL = URL_raw.scheme
        if re_URL[0:2] == "//":
            result = host_URL + ":" + re_URL
        elif re_URL[0:4] == "http":
            result = re_URL
        elif re_URL[0:2] != "//" and re_URL not in black_url:
            if re_URL[0:1] == "/":
                result = host_URL + "://" + ab_URL + re_URL
            else:
                if re_URL[0:1] == ".":
                    if re_URL[0:2] == "..":
                        result = host_URL + "://" + ab_URL + re_URL[2:]
                    else:
                        result = host_URL + "://" + ab_URL + re_URL[1:]
                else:
                    result = host_URL + "://" + ab_URL + "/" + re_URL
        else:
            result = URL
        return result

    def find_last(self,string, str):
        positions = []
        last_position = -1
        while True:
            position = string.find(str, last_position + 1)
            if position == -1: break
            last_position = position
            positions.append(position)
        return positions

    def find_by_url(self,url,rawdata):
        html_raw = rawdata
        if html_raw == None:
            return None
        # print(html_raw)
        html = BeautifulSoup(html_raw, "html.parser")
        html_scripts = html.findAll("script")
        script_array = {}
        script_temp = ""
        for html_script in html_scripts:
            script_src = html_script.get("src")
            if script_src == None:
                script_temp += html_script.get_text() + "\n"
            # else:
            #     purl = self.process_url(url, script_src)
            #     script_array[purl] = self.Extract_html(purl)
        script_array[url] = script_temp
        allurls = []
        for script in script_array:
            # print(script)
            temp_urls = self.extract_URL(script_array[script])
            if len(temp_urls) == 0: continue
            for temp_url in temp_urls:
                allurls.append(self.process_url(script, temp_url))
        result = []
        for singerurl in allurls:
            url_raw = urlparse(url)
            domain = url_raw.netloc
            positions = self.find_last(domain, ".")
            miandomain = domain
            if len(positions) > 1: miandomain = domain[positions[-2] + 1:]
            # print(miandomain)
            suburl = urlparse(singerurl)
            subdomain = suburl.netloc
            # print(singerurl)
            if miandomain in subdomain or subdomain.strip() == "":
                if singerurl.strip() not in result:
                    result.append(singerurl)
        return result


    def find_subdomain(self,urls, mainurl):
        url_raw = urlparse(mainurl)
        domain = url_raw.netloc
        miandomain = domain
        positions = self.find_last(domain, ".")
        if len(positions) > 1: miandomain = domain[positions[-2] + 1:]
        subdomains = []
        for url in urls:
            suburl = urlparse(url)
            subdomain = suburl.netloc
            # print(subdomain)
            if subdomain.strip() == "": continue
            if miandomain in subdomain:
                if subdomain not in subdomains:
                    subdomains.append(subdomain)
        return subdomains


    def giveresult(self,urls, domian):
        if not urls:
            return None
        subdomains = self.find_subdomain(urls, domian)
        return subdomains if subdomains else None


    def main(self,target,rawdata):
        url = target.strip('/ ')
        self._threads = 50
        self._ssl = False
        self.headers= {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"}
        urls = self.find_by_url(url,rawdata)
        subdomains = self.giveresult(urls, url)
        if subdomains:
            return urls,subdomains
        else:
            return urls,None

class DomainAll:
    def __init__(self):
        self.__web_content = []
        self.__raw_url_list = []
        self.__raw_subdomain_list = []
        self.__url_netloc_list = []
        self.__s_key_list, self.__s_hash_list = self.loadfinder()

    def get_favicon_hash(self, url):
        # 尝试从 /favicon.ico 获取 Favicon
        try:
            response = requests.get(url + "/favicon.ico", stream=True, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Google/537.36'},
                                    verify=False,timeout=10)

            if response.status_code == 200:
                favicon_data = response.content
                # 计算 Favicon 的 base64 编码
                favicon_base64 = base64.b64encode(favicon_data)
                # 计算 mmh3 哈希值
                favicon_hash = mmh3.hash(favicon_base64)

                return favicon_hash
            else:
                return None
        except Exception:
            return None

    def get_web_text(self, url):
        # 尝试从 /favicon.ico 获取 Favicon
        try:
            response = requests.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Google/537.36'},
                                    allow_redirects=True, verify=False,timeout=10)
            if response.status_code == 200:
                return response.text, response.headers
            else:
                return None, None
        except Exception:
            return None, None

    def check_keys(self, text, key_list):
        logic = key_list.get('logic', 'or')
        if logic == "and":
            return all(keys in text for keys in key_list['keyword'])
        else:
            return any(keys in text for keys in key_list['keyword'])

    def finder(self, url,hash_flag):
        # s_key_list, s_hash_list = self.loadfinder()
        web_text, header_text = self.get_web_text(url)
        if hash_flag:
            hash = self.get_favicon_hash(url)
            if hash:
                flag = False
                for hash_list in self.__s_hash_list:
                    for hashs in hash_list['keyword']:
                        if hashs == hash:
                            flag = True
                            break
                    if flag:
                        if f"成功识别 {url} 指纹: [b bright_red]{hash_list['cms']}" not in self.__url_netloc_list:
                            OutPrintInfo("Finger", f"成功识别 {url} 指纹: [b bright_red]{hash_list['cms']}")
                            self.__url_netloc_list.append(f"成功识别 {url} 指纹: [b bright_red]{hash_list['cms']}")
                        break

        if web_text or header_text:
            for key_list in self.__s_key_list:
                if (key_list['location'] == "body" or key_list['location'] == "title") and web_text:
                    if self.check_keys(web_text, key_list):
                        if f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}" not in self.__url_netloc_list:
                            OutPrintInfo("Finger", f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}")
                            self.__url_netloc_list.append(f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}")
                        break
                elif key_list['location'] == "header" and header_text:
                    if self.check_keys(header_text, key_list):
                        if f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}" not in self.__url_netloc_list:
                            OutPrintInfo("Finger",f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}")
                            self.__url_netloc_list.append(f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}")
                        break
    def finder_for_cunhuo(self, url,web_text, header_text):
        # s_key_list, s_hash_list = self.loadfinder()
        if web_text or header_text:
            for key_list in self.__s_key_list:
                if (key_list['location'] == "body" or key_list['location'] == "title") and web_text:
                    if self.check_keys(web_text, key_list):
                        if f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}" not in self.__url_netloc_list:
                            # OutPrintInfo("Finger", f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}")
                            self.__url_netloc_list.append(f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}")
                        break
                elif key_list['location'] == "header" and header_text:
                    if self.check_keys(header_text, key_list):
                        if f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}" not in self.__url_netloc_list:
                            # OutPrintInfo("Finger",f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}")
                            self.__url_netloc_list.append(f"成功识别 {url} 指纹: [b bright_red]{key_list['cms']}")
                        break

    def loadfinder(self):
        key_list = []
        hash_list = []
        with open('set/finger.json', 'r') as f:
            data = json.load(f)
            for i in data['finger']:
                if i['method'] == "keyword":
                    key_list.append(i)
                elif i['method'] == "icon_hash":
                    hash_list.append(i)

        return key_list, hash_list
    def fuzz_domaininfoscan(self,domain):

        try:
            url = "https://" + domain
            req = requests.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'},
                               verify=False, timeout=10)
            if req.status_code == 200:
                OutPrintInfo("Nacos", f"[b bright_red]Fuzz成功: {url}")
        except Exception:
            pass
    def nacos_scan(self, ip):
        try:
            url = "http://" + ip + ":8848/nacos"
            req = requests.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'},
                               verify=False, timeout=10)
            if "nacos" in req.text.lower():
                OutPrintInfo("Nacos", f"[b bright_red]发现目标存在Nacos: {url}")
        except Exception:
            pass

    def xxl_scan(self, domain):
        try:
            url = "http://" + domain + "/toLogin"
            req = requests.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'},
                               verify=False, timeout=10)
            if "XXL" in req.text.lower():
                OutPrintInfo("XXL-JOB", f"[b bright_red]发现目标存在XXL-JOB: {url}")
        except Exception:
            pass

    def http_vuln_dir_scan(self, url):
        try:
            req = requests.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'},
                               verify=False, timeout=10)
            if req.status_code == 200 and req.text not in self.__web_content:
                self.__web_content.append(url)
                OutPrintInfo("DIR", f"[[b bright_red]发现敏感路径[/b bright_red]] {url}")
        except Exception:
            pass

    def check_domain(self, domain):
        def run(domain):
            try:
                req = requests.get(domain, headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
                                   verify=False, timeout=10)
                self.finder_for_cunhuo(domain,req.text,req.headers)
                raw = req.content.decode("utf-8", "ignore")
                #
                raw_urls,raw_subdomains = JsFinderScan().main(domain,raw)
                if raw_urls:
                    self.__raw_url_list.extend(raw_urls)
                if raw_subdomains:
                    self.__raw_subdomain_list.extend(raw_subdomains)
                req.encoding = req.apparent_encoding
                soup = BeautifulSoup(req.text, 'html.parser')
                title = soup.title.string
                if not title:
                    title = "N/S"
                return title, req
            except Exception:
                return None, None

        title, req = run(domain)
        if title or req:
            OutPrintInfo("Check-Domain",
                         f"[[b bright_red]URL[/b bright_red]]{domain} | [[b bright_green]TITLE[/b bright_green]]{title} | [[b magenta]LEN[/b magenta]]{str(len(req.text))} | [[b bright_cyan]CODE[/b bright_cyan]]{str(req.status_code)}")
        else:
            OutPrintInfo("Check-Domain", f"[b yellow]DOMAIN {domain} 请求出错")
        return

    def http_server(self, domains):
        h = ["http://", "https://"]
        domain_reslist = []
        for i in domains:
            if i:
                OutPrintInfo("SubDomain", i)
                domain_reslist.extend([k + i for k in h])
        return domain_reslist

    def main(self, target):
        OutPrintInfo("SUBDOMAIN", "由于多个引擎处于外网,建议开启[b bright_red]VPN")
        domain = target["domain"]
        file_flag = target["output"]
        max_ip = int(target["max"])
        if "://" in domain:
            domain = domain.split("://")[-1]
        res = []
        ip_res = []
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Shodan", "开始调用Shodan查找...")
        shodan = Shodan().main(domain)
        if shodan:
            for i in shodan:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Shodan", "Shodan查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Securitytrails", "开始调用Securitytrails查找...")
        sec = SecuritytrailsScan().main(domain)
        if sec:
            for i in sec:
                if i not in res:
                    res.append(i)
        # print(sec)
        OutPrintInfo("Securitytrails", "Securitytrails查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("CERT", "开始调用CERT证书查找...")
        try:
            cert = CERTScan().main(domain)
            if cert:
                for i in cert:
                    if i not in res:
                        res.append(i)
        except Exception as e:
            OverflowError(e)

        # print(cert)
        OutPrintInfo("CERT", "CERT证书查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Virustotal", "开始调用Virustotal查找...")
        vt = Virustotal().main(domain)
        if vt:
            for i in vt:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Virustotal", "Virustotal查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("DnsDumpster", "开始调用DnsDumpster查找...")

        dnsdump_ip, dnsdump_domain = DnsDumpster().main(domain)
        if dnsdump_ip:
            for i in dnsdump_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if dnsdump_domain:
            for i in dnsdump_domain:
                if i not in res:
                    res.append(i)
        # print(dnsdump_domain)
        OutPrintInfo("DnsDumpster", "DnsDumpster查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("Fofa", "开始调用Fofa查找...")
        fofa_ip, fofa_domain = Fofa().main(domain)

        if fofa_ip:
            for i in fofa_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if fofa_domain:
            for i in fofa_domain:
                if i not in res:
                    res.append(i)

        OutPrintInfo("Fofa", "Fofa查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("YT", "开始调用YT查找...")
        yt_ip, yt_domain = Yt().main(domain)
        if yt_ip:
            for i in yt_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if yt_domain:
            for i in yt_domain:
                if i not in res:
                    res.append(i)
        # print(yt_domain)
        OutPrintInfo("YT", "YT查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("Chaziyu", "开始调用Chaziyu查找...")
        chaziyu_domain = Chaziyu().main(domain)
        if chaziyu_domain:
            for i in chaziyu_domain:
                if i not in res:
                    res.append(i)
        # print(chaziyu_domain)
        OutPrintInfo("Chaziyu", "Chaziyu查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("Jldc", "开始调用Jldc查找...")
        jldc_domain = Jldc().main(domain)
        if jldc_domain:
            for i in jldc_domain:
                if i not in res:
                    res.append(i)
        # print(jldc_domain)
        OutPrintInfo("Jldc", "Jldc查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Sitedossier", "开始调用Sitedossier查找...")

        sitedoss_domain = Sitedossier().main(domain)
        if sitedoss_domain:
            for i in sitedoss_domain:
                if i not in res:
                    res.append(i)
        # print(sitedoss_domain)
        OutPrintInfo("Sitedossier", "Sitedossier查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Rapiddns", "开始调用Rapiddns查找...")
        rapiddns_domain = Rapiddns().main(domain)
        if rapiddns_domain:
            for i in rapiddns_domain:
                if i not in res:
                    res.append(i)
        # print(rapiddns_domain)
        OutPrintInfo("Rapiddns", "Rapiddns查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Fullhunt", "开始调用Fullhunt查找...")
        fullhunt_domain = Fullhunt().main(domain)
        if fullhunt_domain:
            for i in fullhunt_domain:
                if i not in res:
                    res.append(i)
        # print(fullhunt_domain)
        OutPrintInfo("Fullhunt", "Fullhunt查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Certspotter", "开始调用Certspotter查找...")
        certspotter_domian = Certspotter().main(domain)
        if certspotter_domian:
            for i in certspotter_domian:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Certspotter", "Certspotter查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("Hackertarget", "开始调用Hackertarget查找...")
        hackertarget_ip,hackertarget_domain = Hackertarget().main(domain)
        if hackertarget_domain:
            for i in hackertarget_domain:
                if i not in res:
                    res.append(i)
        if hackertarget_ip:
            for i in hackertarget_ip:
                if i not in ip_res:
                    ip_res.append(i)
        OutPrintInfo("Hackertarget", "Hackertarget查找结束")

        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Archive", "开始调用Archive查找...")
        archive_domain = Archive().main(domain)
        if archive_domain:
            for i in archive_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Archive", "Archive查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Dnshistory", "开始调用Dnshistory查找...")
        dnshistor_domain = Dnshistory().main(domain)
        if dnshistor_domain:
            for i in dnshistor_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Dnshistory", "Dnshistory查找结束")

        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Binaryedge", "开始调用Binaryedge查找...")
        binaryedge_domain = Binaryedge().main(domain)
        if binaryedge_domain:
            for i in binaryedge_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Binaryedge", "Binaryedge查找结束")

        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Whoisxmlapi", "开始调用Whoisxmlapi查找...")
        whoisxmlapi_domain = Whoisxmlapi().main(domain)
        if whoisxmlapi_domain:
            for i in whoisxmlapi_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Whoisxmlapi", "Whoisxmlapi查找结束")

        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Google", "开始调用Google查找...")
        google_domain = Google().main(domain)
        if google_domain:
            for i in google_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Google", "Google查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Alienvault", "开始调用Alienvault查找...")
        alienvaul_ip, alienvaul_domain = Alienvault().main(domain)
        if alienvaul_domain:
            for i in alienvaul_domain:
                if i not in res:
                    res.append(i)
        if alienvaul_ip:
            for i in alienvaul_ip:
                if i not in ip_res:
                    ip_res.append(i)
        OutPrintInfo("Alienvault", "Alienvault查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("Quake", "开始通过Quake搜索域名IP信息...")
        quake_domain, quake_ip = Quake_Domain().main(domain)
        if quake_ip:
            for i in quake_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if quake_domain:
            for i in quake_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Quake", "Quake搜索域名IP信息结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("ZoomEye", "开始通过Zoomeye搜索域名IP信息...")
        try:
            OutPrintInfo("ZoomEye", "检查是否出网...")
            resp = requests.get("https://www.google.com.hk/",headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Google/537.3"})

            if resp.status_code == 200:
                OutPrintInfo("ZoomEye", "出网正常,开始使用HK接口...")
                zoomeye_domain = ZoomEyeHK().main(domain)
                if zoomeye_domain:
                    for i in zoomeye_domain:
                        if i not in res:
                            res.append(i)
            else:
                OutPrintInfo("ZoomEye", "出网失败,开始使用ORG接口...")
                zoomeye_ip, zoomeye_domain = ZoomEye().main(domain)
                if zoomeye_ip:
                    for i in zoomeye_ip:
                        if i not in ip_res:
                            ip_res.append(i)
                if zoomeye_domain:
                    for i in zoomeye_domain:
                        if i not in res:
                            res.append(i)
        except Exception:
            OutPrintInfo("ZoomEye", "ZoomEye代理验证或接口请求出错")

        OutPrintInfo("ZoomEye", "ZoomEye搜索域名IP信息结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)


        OutPrintInfo("HunterHow", "开始通过HunterHow搜索域名及IP信息...")
        hunterhow_domain, hunterhow_ip = HunterHow().main(domain)
        if hunterhow_ip:
            for i in hunterhow_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if hunterhow_domain:
            for i in hunterhow_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("HunterHow", "HunterHow搜索域名IP信息结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("DayDayMap", "开始通过DayDayMap搜索域名及IP信息...")
        daydaymap_domain, daydaymap_ip = DayDayMap().main(domain)
        if daydaymap_ip:
            for i in daydaymap_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if daydaymap_domain:
            for i in daydaymap_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("DayDayMap", "DayDayMap搜索域名IP信息结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)


        OutPrintInfo("C99NL", "开始通过C99NL搜索域名及IP信息...")
        c99nl_domain, c99nl_ip = C99NL().main(domain)
        if c99nl_ip:
            for i in c99nl_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if c99nl_domain:
            for i in c99nl_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("C99NL", "C99NL搜索域名IP信息结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)


        OutPrintInfo("Netlas", "开始通过Netlas搜索域名IP信息...")
        netlas_domain, netlas_ip = Netlas().main(domain)
        if netlas_ip:
            for i in netlas_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if netlas_domain:
            for i in netlas_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Netlas", "Netlas搜索域名IP信息结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("Securitytrails", "开始通过Securitytrails搜索域名IP信息...")
        sec_ip = SecuritytrailsIPScan().main(domain)
        if sec_ip:
            for i in sec_ip:
                if i not in ip_res:
                    ip_res.append(i)
        OutPrintInfo("Securitytrails", "Securitytrails查找IP结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("Censys", "开始通过Censys搜索域名IP信息...")
        censys_ip = CensysDomainInfo().main(domain)
        if censys_ip:
            for i in censys_ip:
                if i not in ip_res:
                    ip_res.append(i)
        OutPrintInfo("Censys", "Censys搜索域名IP信息结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("ViewDNS", "开始调用ViewDNS查找...")
        viwedns_domain = ViewDNS().main(domain)
        if viwedns_domain:
            for i in viwedns_domain:
                if i not in ip_res:
                    ip_res.append(i)

        OutPrintInfo("ViewDNS", "ViewDNS查找结束")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)

        OutPrintInfo("Working", "查找结果如下")

        if res:
            domain_reslist = self.http_server(res)

            def mingan_dir():
                spring_list = ["actuator/env", "actuator", "docs", "nacos", "docs.html", "api/docs","api/docs.html", "api-docs",
                               "swagger/swagger-ui.html", "web/.env", "VwmRIfEYDH.php", "manager", "metrics", "phpinfo",
                               ".svn/entries", "api/swagger-ui.html", ".env", "WEB-INFO", "mysql_config.ini","xxl-job-admin","phpinfo.php","info.php"]
                res_http_vuln_check_url_list = [http_domain + "/" + k for http_domain in domain_reslist for k in
                                                spring_list]
                OutPrintInfo("Working", "开始检测敏感路径...")
                tasks = progress.add_task("[b cyan]开始检测敏感路径...", total=len(res_http_vuln_check_url_list))
                with ThreadPoolExecutor(max_workers=80) as executor:
                    futures = [executor.submit(self.http_vuln_dir_scan, dir_res.strip()) for dir_res in
                               res_http_vuln_check_url_list]
                    for future in as_completed(futures):
                        future.result()
                        progress.update(tasks, advance=1)
                wait(futures)
                OutPrintInfo("Working", "敏感路径检测结束")
                self.__web_content = []
            def domain_for_xxl_scan():
                OutPrintInfo("Working", "开始检测XXL-JOB存活...")
                tasks = progress.add_task("[b cyan]开始检测XXL-JOB存活...", total=len(res))
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = [executor.submit(self.xxl_scan, http_domain.strip()) for http_domain in res]
                    for future in as_completed(futures):
                        future.result()
                        progress.update(tasks, advance=1)
                wait(futures)
                OutPrintInfo("Working", "XXL-JOB存活检测结束")
            def cunhuo_url():
                OutPrintInfo("Working", "开始检测存活及指纹...")
                tasks = progress.add_task("[b cyan]开始检测存活及指纹...", total=len(domain_reslist))
                with ThreadPoolExecutor(50) as pool:
                    fs = [pool.submit(self.check_domain, ck_domain) for ck_domain in domain_reslist if ck_domain]
                    for f in as_completed(fs):
                        f.result()
                        progress.update(tasks, advance=1)
                wait(fs)
                for i in self.__url_netloc_list:
                    OutPrintInfo("Working", i)
                OutPrintInfo("Working", "检测存活及指纹结束")
            def finger_url():
                OutPrintInfo("Working", "开始检测网站HASH指纹...")
                # tasks = progress.add_task("[b cyan]开始网站指纹...", total=len(domain_reslist))
                tasks = progress.add_task("[b cyan]开始网站HASH指纹扫描...", total=len(domain_reslist))
                with ThreadPoolExecutor(50) as pool:
                    fs = [pool.submit(self.finder, ck_domain,False) for ck_domain in domain_reslist if ck_domain]
                    for f in as_completed(fs):
                        f.result()
                        progress.update(tasks, advance=1)
                wait(fs)
                OutPrintInfo("Working", "网站HASH指纹检测结束")
            def finger_js_url():
                OutPrintInfo("Working", "开始检测网站JS指纹检测...")
                for js_url in self.__raw_url_list:
                    if "admin" in js_url or "login" in js_url:
                        OutPrintInfo("Working", f"JS中发现的敏感路径: {js_url}")
                # tasks = progress.add_task("[b cyan]开始网站指纹...", total=len(domain_reslist))
                tasks = progress.add_task("[b cyan]开始网站JS指纹扫描...", total=len(self.__raw_url_list))
                with ThreadPoolExecutor(50) as pool:
                    fs = [pool.submit(self.finder, ck_domain,True) for ck_domain in self.__raw_url_list if ck_domain]
                    for f in as_completed(fs):
                        f.result()
                        progress.update(tasks, advance=1)
                wait(fs)
                for i in self.__raw_subdomain_list:
                    if i:
                        OutPrintInfo("Working", f"指纹识别找到的域名信息:[b bright_red] {i}")
                self.__url_netloc_list = []
                self.__raw_url_list = []
                self.__raw_subdomain_list = []
                OutPrintInfo("Working", "网站JS指纹检测结束")
            def ip_for_nacos_scan():
                OutPrintInfo("Working", "开始检测Nacos存活...")
                tasks = progress.add_task("[b cyan]开始检测Nacos存活...", total=len(res))
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = [executor.submit(self.nacos_scan, nacos_ip.strip()) for nacos_ip in ip_res]
                    for future in as_completed(futures):
                        future.result()
                        progress.update(tasks, advance=1)
                wait(futures)
                OutPrintInfo("Working", "Nacos存活检测结束")
            def domain_fuzzscan():
                OutPrintInfo("Working", "开始进行FUZZ-Domain检测...")
                fuzz_list = []
                fuzz_dict = ['nacos','xxl','apollo','admin','houtai','ht']
                base_domain = domain.split('.')[-2]
                for i in range(1, len(base_domain) + 1):
                    for b in fuzz_dict:
                        patterns = [
                            f"{base_domain[:i]}{b}.{domain}",
                            f"{base_domain[:i]}-{b}.{domain}",
                            f"{b}{base_domain[:i]}.{domain}",
                            f"{b}-{base_domain[:i]}.{domain}",
                            f"{base_domain[:i]}_{b}.{domain}",
                            f"{b}_{base_domain[:i]}.{domain}"
                        ]
                        fuzz_list.extend(patterns)
                tasks = progress.add_task("[b cyan]开始FUZZ-Domain...", total=len(fuzz_list))
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = [executor.submit(self.fuzz_domaininfoscan, fuzzdomain.strip()) for fuzzdomain in fuzz_list]
                    for future in as_completed(futures):
                        future.result()
                        progress.update(tasks, advance=1)
                wait(futures)
                OutPrintInfo("Working", "FUZZ-Domain检测结束")
            def poc_list():
                from cve.Nginx.Nginx_File_Read import Nginx_File_Read_Scan
                from cve.Jquery.JqueryDirRead import JqueryDirReadScan
                from cve.NodeJs.CVE_2017_14849 import Cve_2017_14849
                from cve.NodeJs.CVE_2021_21315 import Cve_2021_21315
                from cve.Ruby.CVE_2018_3760 import Cve_2018_3760
                from cve.Aiohttp.CVE_2024_23334 import Cve_2024_23334
                from cve.Ruby.CVE_2019_5418 import Cve_2019_5418
                from cve.Spring.SpringDump import SpringDumpScan
                from cve.Apache.Log4j_Check import Log4j_Check_Run
                from cve.Shiro.Shiro_Check import Shiro_Check_Run
                from cve.IIS.IISPut import IISPutScan
                from cve.Mini_Httpd.CVE_2018_18778 import Cve_2018_18778
                from cve.ZOHO.CVE_2023_35854 import Cve_2023_35854
                from cve.SolarWinds.SolarWinds_File_Read import SolarWinds_File_Read_Scan
                from cve.PHP.CVE_2024_4577 import Cve_2024_4577
                poc_list = [
                    Nginx_File_Read_Scan,
                    JqueryDirReadScan,
                    Cve_2017_14849,
                    Cve_2021_21315,
                    Cve_2018_3760,
                    Cve_2019_5418,
                    SpringDumpScan,
                    Shiro_Check_Run,
                    IISPutScan,
                    Cve_2018_18778,
                    Cve_2023_35854,
                    Log4j_Check_Run,
                    Cve_2024_23334,
                    SolarWinds_File_Read_Scan,
                    Cve_2024_4577
                ]

                tasks = progress.add_task("[b cyan]常归漏洞扫描...", total=len(poc_list) * len(domain_reslist))
                with ThreadPoolExecutor(50) as pool:
                    futures = [pool.submit(poc().main, {"url": url.strip(), "ssl": False,
                                                        "header": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                                        "proxy": None, "timeout": 10, "cmd": "whoami",
                                                        "file": "etc/passwd", "batch_work": True}) for poc in poc_list
                               for url in domain_reslist]
                    for future in as_completed(futures):
                        future.result()
                        progress.update(tasks, advance=1)
                wait(futures)

            url_tance_list = [
                cunhuo_url,
                finger_url,
                finger_js_url,
                mingan_dir,
                poc_list,
                domain_for_xxl_scan,
                domain_fuzzscan
            ]


            if ip_res:
                url_tance_list.append(ip_for_nacos_scan)
            with Progress(transient=True) as progress:
                tasks = progress.add_task("[b cyan]URL探测总进度...", total=len(url_tance_list))
                for task in url_tance_list:
                    try:
                        task()
                    except Exception as e:
                        OutPrintInfo("Err", e)
                    progress.update(tasks, advance=1)
            time.sleep(0.5)

        if ip_res:
            OutPrintInfo("Working", "以下是查找IP结果:")
            for i in ip_res:
                OutPrintInfo("IP", i)
            # OutPrintInfo("Working", "[b bright_red]~" * 60)
            OutPrintInfo("Working", "开始通过返回IP进行回调查找域名...")

            if len(ip_res) > max_ip:
                OutPrintInfo("Working", f"检测到IP数量过多,取前[b bright_red]{str(max_ip)}[/b bright_red]进行检测...")
                res.append("以下是二次IP回调域名")
                for i in ip_res[0:max_ip]:
                    if i:
                        sec_domains = Work().main(i)
                        if sec_domains:
                            # res.append("以下是二次IP回调域名")
                            for d in sec_domains:
                                if d not in res:
                                    if d:
                                        res.append(d)
                                        OutPrintInfo("SubDomain", d)
            else:
                res.append("以下是二次IP回调域名")
                for i in ip_res:
                    if i:
                        sec_domains = Work().main(i)
                        if sec_domains:
                            for d in sec_domains:
                                if d:
                                    if d not in res:
                                        res.append(d)
                                        OutPrintInfo("SubDomain", d)


        if file_flag:
            file_name = domain.replace('.', '_')
            for ds in res:
                with open(f"./result/{file_name}_info.txt", "a") as w:
                    w.write(ds + "\n")
            for ips in ip_res:
                with open(f"./result/{file_name}_info.txt", "a") as w:
                    w.write(ips + "\n")
            # OutPrintInfo("Working", "[b bright_red]~" * 60)
            OutPrintInfo("Working", f"结果输出到result/{file_name}_info.txt")
        # OutPrintInfo("Working", "[b bright_red]~" * 60)
        OutPrintInfo("Working", "回调查找域名执行结束")
