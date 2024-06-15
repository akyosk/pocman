#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr
class Cmd5:
    def main(self,target):
        email = target["mail"]
        key = target["key"]
        hash = target["hash"]
        try:
            OutPrintInfo("CMD5", f"开始解密HASH: {hash}")
            req = requests.get(f"http://www.cmd5.com/api.ashx?email={email}&key={key}&hash={hash}")
            if "CMD5-ERROR:0" in req.text:
                OutPrintInfoErr("解密失败")
            elif "CMD5-ERROR:-1" in req.text:
                OutPrintInfoErr("无效的用户名密码")
            elif "CMD5-ERROR:-2" in req.text:
                OutPrintInfoErr("余额不足")
            elif "CMD5-ERROR:-3" in req.text:
                OutPrintInfoErr("解密服务器故障")
            elif "CMD5-ERROR:-4" in req.text:
                OutPrintInfoErr("不识别的密文")
            elif "CMD5-ERROR:-7" in req.text:
                OutPrintInfoErr("不支持的类型")
            elif "CMD5-ERROR:-8" in req.text:
                OutPrintInfoErr("api权限被禁止")
            elif "CMD5-ERROR:-999" in req.text:
                OutPrintInfoErr("其它错误")
            elif "CMD5-ERROR:-9" in req.text:
                OutPrintInfoErr("条数超过100条")
            else:
                OutPrintInfo("CMD5",f"HASH解密结果为: req.text.strip()")
            OutPrintInfo("CMD5", f"解密结束")
        except Exception:
            OutPrintInfoErr("请求cmd5发生错误")