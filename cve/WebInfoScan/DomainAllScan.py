from bs4 import BeautifulSoup
import re
import feedparser
import concurrent.futures
import dns.resolver
import json
import base64
import requests
from urllib.parse import quote
from libs.public.outprint import OutPrintInfo
from set.config import api_list,censys_api,shodan_api,virustotal_api,dnsdump_csrftoken,fofa_email,fofa_key,yt_key,viewdns_key

class CERTScan:
    def get_rss_for_domain(self, domain):
        # print(domain)
        """Pull the domain identity information from CERT.sh"""
        OutPrintInfo("CERT",f"Retrieving information about [b bright_red]{domain}[/b bright_red] from CERT.sh...")
        results_raw = requests.get(self.base_url.format(domain)).content
        results_entries = feedparser.parse(results_raw)["entries"]
        OutPrintInfo("CERT","Retrieval of info done.")
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
                OutPrintInfo("CERT","DNS resolution turned on.")
                final_results = []
                for cur_result in sorted_results:
                    if "*" not in cur_result:
                        OutPrintInfo("CERT",f"Resolving {cur_result}...")
                        try:
                            ip_addresses = dns.resolver.query(cur_result)
                            for ip_address in ip_addresses:
                                final_results.append("{}\t{}".format(cur_result, ip_address))
                        except dns.resolver.NoAnswer:
                            final_results.append(cur_result)
                        OutPrintInfo("CERT","... done.")
                    else:
                        final_results.append(cur_result)
            except Exception as e:
                OutPrintInfo("CERT","[b bright_yellow]未能从CERT搜索到目标信息或者连接出错")
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
            OutPrintInfo("CERT",f"通过证书共找到 [b bright_red]{str(len(final_results))}[/b bright_red] 个子域名")
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
                    OutPrintInfo("Securitytrails", "[b bright_red]Securitytrails接口已没有查询数量使用,需要更换Key :(")
                    return "You've exceeded the usage limits for your account."
                if domains == "None":
                    return "None"
                else:
                    domain_url = [res + '.' + res_domain for res in domains]
                    OutPrintInfo("Securitytrails", f"任务执行完成Securitytrails共找到 [b bright_red]{len(domains)}[/b bright_red] 个子域名")
                    return domain_url
            else:
                OutPrintInfo("Securitytrails", "[b bright_yellow]未能在Securitytrails匹配到相关结果 :(")
                return False
        except Exception as e:
            OutPrintInfo("Securitytrails", "[b bright_yellow]无法连接Securitytrails或者没有匹配到相关结果 :(")
            return False

    def _check(self):
        # domainRes = None
        flag = False
        res = self._api_scan_work(self._api_list[0])
        if res:
            if res == "You've exceeded the usage limits for your account.":
                return False
            if res == "None":
                return False
            return res

        else:
            num = 1
            for i in self._api_list[1:]:
                res_twice = self._api_scan_work(i)
                if res_twice:
                    return res_twice
                else:
                    OutPrintInfo("WEB-API",f"目前有[b bright_red]{num}[/b bright_red]个接口免费数量已经全部使用，剩余[b bright_red]{len(self._api_list) - num}[/b bright_red]个接口待测")
                    num += 1
                    if num == len(self._api_list):
                        flag = False
        if not flag:
            return False


    def main(self,target):
        self._url = target
        if self._url:
            OutPrintInfo("Securitytrails","开始通过接口查找子域名......")

            res = self._check()
            if res:
                OutPrintInfo("Securitytrails","接口信息查询结束")
                return res
            else:
                OutPrintInfo("Securitytrails","[b bright_yellow]接口没有免费查询数量或没有获取到相关结果 :(")
                return None
        else:
            OutPrintInfo("Securitytrails","[b bright_yellow]目标不具备子域名搜索条件 :(")
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
                OutPrintInfo("Securitytrails", "[b bright_yellow]Securitytrails-Key没有查询次数 :(")
                return "You've exceeded the usage limits for your account."

            json_bytes = json.loads(response.text)
            records = json_bytes['records']
            if json_bytes['records']:
                for j in records:
                    for res in j['values']:
                        res_dns = res['ip']
                        if res_dns not in ips_list:
                            ips_list.append(res_dns)
                OutPrintInfo("Securitytrails",f"任务执行完成Securitytrails共找到 [b bright_red]{str(len(ips_list))}[/b bright_red] 个IP")
                return ips_list
            else:
                OutPrintInfo("Securitytrails", "[b bright_yellow]Securitytrails没有匹配到IP相关结果 :(")
                return "None"
        except Exception:
            OutPrintInfo("Securitytrails", "[b bright_yellow]无法连接Securitytrails或者没有匹配到IP相关结果 :(")
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
            OutPrintInfo("Securitytrails", "[b bright_yellow]无法连接Securitytrails或者没有匹配到IP相关结果 :(")
            return False

    def _check(self):
        flag = False
        res = self._api_scan_work(self._api_list[0])
        if res:
            if res == "None":
                return False
            if res == "You've exceeded the usage limits for your account.":
                return False
            return res
        else:
            num = 1
            for i in self._api_list[1:]:
                res_twice = self._api_scan_work(i)
                if res_twice:
                    return res_twice
                else:
                    OutPrintInfo("Securitytrails",f"目前有[b bright_red]{num}[/b bright_red]个接口免费数量已经全部使用，剩余[b bright_red]{len(self._api_list) - num}[/b bright_red]个接口待测")
                    num += 1
                    if num == len(self._api_list):
                        flag = False
        if not flag:
            return False


    def main(self,target):
        self._url = target
        if '://' in self._url:
            domain = self._url.split('://')[-1]
        else:
            domain = self._url
        pattern = r'[a-zA-Z]'
        data_check = bool(re.search(pattern, domain))
        if data_check:
            OutPrintInfo("Securitytrails","开始通过接口查找历史IP......")
            res = self._check()
            if res:
                OutPrintInfo("Securitytrails", "接口信息查询结束")
                return res
            else:
                OutPrintInfo("Securitytrails", "[b bright_yellow]Securitytrails没有匹配到IP相关结果 :(")
                return None
        else:
            OutPrintInfo("Securitytrails", "[b bright_yellow]目标不具备子域名搜索条件 :(")
            return None

class Shodan:
    def __init__(self):
        self.domain = None
    def shodan_perform_nslookup(self,subdomain):
        domain = subdomain + '.' + self.domain
        return domain

    def main(self,target):
        self.domain = target
        if "://" in self.domain:
            self.domain = self.domain.split("://")[-1]

        URL = 'https://www.shodan.io/domain/' + self.domain
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            "Cookie": shodan_api,
        }
        try:

            response_page = requests.get(URL,headers=header)
            my_soup = BeautifulSoup(response_page.content, 'html.parser')
            subs = my_soup.find_all('div', 'card card-padding card-light-blue')
            results = []

            with concurrent.futures.ThreadPoolExecutor() as executor:
                subdomains = []
                for sub in subs:
                    find = re.findall('<li>.*?</li>', str(sub))
                    match = [re.sub('<li>|</li>', '', s) for s in find]
                    subdomains.extend(match)

                futures = [executor.submit(self.shodan_perform_nslookup, subdomain) for subdomain in subdomains]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    results.append(result)

            if results:
                OutPrintInfo("Shodan", f"任务执行完成Shodan共找到 [b bright_red]{str(len(result))}[/b bright_red] 个子域名")
                return results
            else:
                OutPrintInfo("Shodan", "[b bright_yellow]Shodan未能匹配到结果或没有查询次数 :(")
                return None
        except Exception:
            OutPrintInfo("Shodan", "[b bright_yellow]Shodan连接出错或者无匹配结果 :(")
            return None

class CensysDomainInfo:
    def main(self,target):
        domain = target
        cookie = censys_api
        if '://' in target:
            domain = target.split('://')[-1]
        if not cookie:
            OutPrintInfo("Censys","未检测到Censys-Token")
            return None
        ip_list = []
        url = f'https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names%3A+{domain}&per_page=100&virtual_hosts=EXCLUDE'
        header = {
            'accept': 'application/json',
            'Authorization': cookie
        }
        try:
            response = requests.get(url,headers=header).json()
            lis = response['result']['hits']

            for i in lis:
                if i not in ip_list:
                    ip_list.append(i["ip"])
            if ip_list:
                OutPrintInfo("Shodan",f"任务执行完成Shodan共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return ip_list
        except Exception:
            OutPrintInfo("Censys","[b bright_yellow]Censys无法连接或者未匹配到相关信息 :(")
            return None

class Work:
    def fofa(self,ip):
        res = FofaIp().main(ip)
        return res if res else None
    def vt(self,ip):
        res = VirustotalIP().main(ip)
        return res if res else None
    def sec(self,ip):
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
    def yt(self,ip):
        res = YtIp().main(ip)
        return res if res else None
    def main(self,ip):
        domain_list = []
        res1 = self.sec(ip)
        res2 = self.vt(ip)
        res3 = self.fofa(ip)
        res4 = self.yt(ip)
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
        return domain_list if domain_list else None

class Virustotal:
    def main(self,domian):
        domain_list = []
        url = f"https://www.virustotal.com/api/v3/domains/{domian}/relationships/subdomains?limit=100"
        if not virustotal_api:
            OutPrintInfo("Virustotal","[b cyan]未检测到Virustotal-Api-Key,不执行Virustotal相关操作")
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
                OutPrintInfo("Virustotal", f"任务执行完成Virustotal共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            else:
                OutPrintInfo("Virustotal", "[b bright_yellow]Virustotal未搜索到相关结果 :(")
            return domain_list if domain_list else None
        except Exception:
            OutPrintInfo("Virustotal","[b bright_yellow]Virustotal无法连接或者未匹配到相关信息 :(")
            return None

class VirustotalIP:
    def main(self,ip):
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
    def main(self,domain):
        if not dnsdump_csrftoken:
            OutPrintInfo("DnsDumpster","[b cyan]未检测到Dnsdump-csrftoken,不执行Dnsdump-csrftoken相关操作")
            return
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
            OutPrintInfo("DnsDumpster", f"任务执行完成DnsDumpster共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
            OutPrintInfo("DnsDumpster", f"任务执行完成DnsDumpster共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")

            return ip_list,domain_list
        except Exception:
            OutPrintInfo("DnsDumpster","[b bright_yellow]DnsDumpster未能获取到相关结果或无法连接 :(")
            return None,None

class Fofa:
    def main(self,domain):
        if not fofa_key:
            OutPrintInfo("Fofa","[b cyan]未检测到Fofa-Key,不执行Fofa相关操作")
            return None,None
        ip_list = []
        domain_list = []
        query = f'domain="{domain}"'
        base64_str = base64.b64encode(query.encode('utf-8')).decode()
        query_str = quote(base64_str)

        url = f"https://fofa.info/api/v1/search/all?email={fofa_email}&key={fofa_key}&qbase64={query_str}&size=100"
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
                return ip_list,domain_list
            else:
                OutPrintInfo("DnsDumpster", "[b bright_yellow]Fofa查询出错,检测Key是否可用 :(")
        except Exception:
            OutPrintInfo("DnsDumpster","[b bright_yellow]Fofa未能获取到相关结果或无法连接 :(")
            return None, None

class FofaIp:
    def main(self,ip):
        if not fofa_key:
            # OutPrintInfo("Fofa","[b cyan]未检测到Fofa-Key,不执行Fofa相关操作")
            return None
        domain_list = []
        query = f'ip="{ip}"'
        base64_str = base64.b64encode(query.encode('utf-8')).decode()
        query_str = quote(base64_str)

        url = f"https://fofa.info/api/v1/search/all?email={fofa_email}&key={fofa_key}&qbase64={query_str}&size=100"
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
            # OutPrintInfo("DnsDumpster","[b bright_yellow]Fofa未能获取到相关结果或无法连接 :(")
            return None, None
class Yt:
    def main(self,domain):
        search = f'domain="{domain}"'
        search = base64.urlsafe_b64encode(search.encode("utf-8")).decode()
        # print("search:", search)
        if not yt_key:
            OutPrintInfo("YT","[b cyan]未检测到YT-Key,不执行YT相关操作")
            return None,None
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
                OutPrintInfo("YT",f"任务执行完成YT共找到 [b bright_red]{str(len(domain_list))}[/b bright_red] 个子域名")
                OutPrintInfo("YT",f"任务执行完成YT共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
                return ip_list,domain_list
            else:
                OutPrintInfo("YT", "[b bright_yellow]使用YT未查询成功,检测Key是否可用 :(")
                return None,None
        except Exception:
            OutPrintInfo("YT", "[b bright_yellow]使用YT未查询成功,检测Key是否可用 :(")
            return None, None
class YtIp:
    def main(self,ip):
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
                # OutPrintInfo("YT", "[b bright_yellow]使用YT未查询成功,检测Key是否可用 :(")
                return None
        except Exception:
            # OutPrintInfo("YT", "[b bright_yellow]使用YT未查询成功,检测Key是否可用 :(")
            return None
class ViewDNS:
    def main(self,domain):
        url = f"https://api.viewdns.info/iphistory/?domain={domain}&apikey={viewdns_key}&output=json"
        ip_list = []
        if not viewdns_key:
            OutPrintInfo("YT","[b cyan]未检测到ViewDNS-Key,不执行ViewDNS相关操作")
            return
        try:
            req = requests.get(url)
            if 'Please select a different hostname and try again' in req.text:
                OutPrintInfo("ViewDNS", "[b bright_yellow]使用ViewDNS未查询到相关结果 :(")
                return None
            res_json = json.loads(req.text)
            for i in res_json['response']['records']:
                if i['ip'] not in ip_list:
                    ip_list.append(i['ip'])
            OutPrintInfo("ViewDNS",f"任务执行完成ViewDNS共找到 [b bright_red]{str(len(ip_list))}[/b bright_red] 个IP")
            return ip_list
        except Exception:
            OutPrintInfo("ViewDNS", "[b bright_yellow]使用ViewDNS未查询成功,检测Key是否可用 :(")

class DomainAll:
    def main(self,target):
        OutPrintInfo("SUBDOMAIN", "建议开启[b bright_red]VPN[/b bright_red]")
        domain = target[0]
        file_flag = target[1]
        if "://" in domain:
            domain = domain.split("://")[-1]
        res = []
        ip_res= []
        OutPrintInfo("Shodan","开始调用Shodan查找...")
        shodan = Shodan().main(domain)
        if shodan:
            for i in shodan:

                if i not in res:
                    res.append(i)
        OutPrintInfo("Shodan", "Shodan查找结束")
        OutPrintInfo("Securitytrails", "开始调用Securitytrails查找...")
        sec = SecuritytrailsScan().main(domain)
        if sec:
            for i in sec:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Securitytrails", "Securitytrails查找结束")

        OutPrintInfo("CERT", "开始调用CERT证书查找...")
        cert = CERTScan().main(domain)
        if cert:
            for i in cert:
                if i not in res:
                    res.append(i)
        OutPrintInfo("CERT", "CERT证书查找结束")
        OutPrintInfo("Virustotal", "开始调用Virustotal查找...")
        vt = Virustotal().main(domain)
        if vt:
            for i in vt:
                if i not in res:
                    res.append(i)
        OutPrintInfo("Virustotal", "Virustotal查找结束")

        OutPrintInfo("DnsDumpster", "开始调用DnsDumpster查找...")

        dnsdump_ip,dnsdump_domain = DnsDumpster().main(domain)
        if dnsdump_ip:
            for i in dnsdump_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if dnsdump_domain:
            for i in dnsdump_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("DnsDumpster", "DnsDumpster查找结束")

        OutPrintInfo("Fofa", "开始调用Fofa查找...")
        fofa_ip,fofa_domain = Fofa().main(domain)
        if fofa_ip:
            for i in fofa_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if fofa_domain:
            for i in fofa_domain:
                if i not in res:
                    res.append(i)

        OutPrintInfo("Fofa", "Fofa查找结束")
        OutPrintInfo("YT", "开始调用YT查找...")
        yt_ip,yt_domain = Yt().main(domain)
        if yt_ip:
            for i in yt_ip:
                if i not in ip_res:
                    ip_res.append(i)
        if yt_domain:
            for i in yt_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("YT", "YT查找结束")

        OutPrintInfo("ViewDNS", "开始调用ViewDNS查找...")
        viwedns_domain = ViewDNS().main(domain)
        if viwedns_domain:
            for i in viwedns_domain:
                if i not in res:
                    res.append(i)
        OutPrintInfo("ViewDNS", "ViewDNS查找结束")

        OutPrintInfo("IP", "开始通过Securitytrails搜索域名IP信息...")
        sec_ip = SecuritytrailsIPScan().main(domain)
        if sec_ip:
            for i in sec_ip:
                if i not in ip_res:
                    ip_res.append(i)
        OutPrintInfo("IP", "Securitytrails查找IP结束")

        OutPrintInfo("IP", "开始通过Censys搜索域名IP信息...")
        censys_ip = CensysDomainInfo().main(domain)
        if censys_ip:
            for i in censys_ip:
                if i not in ip_res:
                    ip_res.append(i)
        OutPrintInfo("IP", "Censys搜索域名IP信息结束")



        OutPrintInfo("Work", "查找结果如下")
        if res:
            for i in res:
                OutPrintInfo("SubDomain",i)

        if ip_res:
            for i in ip_res:
                OutPrintInfo("IP", i)
        OutPrintInfo("Work", "开始通过返回IP进行回调查找域名...")
        for i in ip_res:
            sec_domains = Work().main(i)
            if sec_domains:
                res.append("以下是二次IP回调域名")
                for d in sec_domains:
                    if d not in res:
                        res.append(d)
                        OutPrintInfo("SubDomain",d)
        if file_flag:
            for ds in res:
                with open("./result/domainIpInfo.txt", "a") as w:
                    w.write(ds + "\n")
            for ips in ip_res:
                with open("./result/domainIpInfo.txt", "a") as w:
                    w.write(ips + "\n")
            OutPrintInfo("Work", "结果输出到result/domainIpInfo.txt")
        OutPrintInfo("Work", "回调查找域名执行结束")




