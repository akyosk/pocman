import urllib3,requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()
class ClickHouse_Sql_Scan:
    def run(self,url):
        base_url = url + "/?query=show%20status"
        try:
            response = requests.get(base_url,headers=self.headers,verify=self.ssl,proxies=self.proxy)
            if "Code: 62" in response.text:
                OutPrintInfoSuc("ClickHouse", f"目标存在漏洞:{base_url}")
                if not self.batch:
                    OutPrintInfo("ClickHouse", f"执行结果:")
                    OutPrintInfo("ClickHouse", f"响应:\n{response.text.strip()}")
                else:
                    OutPutFile("clickhouse_sql.txt",f"目标存在漏洞: {base_url}")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("ClickHouse", "目标不存在ClickHouse API数据库接口未授权访问漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("ClickHouse", "目标请求出错")
                return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(header=headers, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=headers)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("ClickHouse", f"开始检测ClickHouse API数据库接口未授权访问漏洞...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("ClickHouse", f"ClickHouse API数据库接口未授权访问漏洞检测结束")