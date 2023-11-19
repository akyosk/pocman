#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo

urllib3.disable_warnings()


class SkywalkingSqlScan:

    def run(self, urls):
        try:
            url = urls + '/graphql'
            data = """{
    "query":"query queryLogs($condition: LogQueryCondition) {
  queryLogs(condition: $condition) {
    total
    logs {
      serviceId
      serviceName
      isError
      content
    }
  }
}
",
    "variables":{
        "condition":{
            "metricName":"sqli",
            "state":"ALL",
            "paging":{
                "pageSize":10
            }
        }
    }
}"""
            header = {
                "User-Agent":self.headers,
                "Content-Type": "application/json",
                "Accept-Encoding": "gzip, deflate",
            }
            response = requests.post(url,headers=header,data=data, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "SQLI" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("Skywalking", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/skywalkingSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass

    def main(self, target):
        # OutPrintInfo("DocCms", '开始检测SQL注入...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        self.headers = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        self.proxy = {"http":proxy,"https":proxy}

        self.run(url)

        # OutPrintInfo("DocCms", 'SQL注入检测结束')