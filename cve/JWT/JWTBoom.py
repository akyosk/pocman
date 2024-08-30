#!/usr/bin/env python 3
# -*- coding: utf-8 -*-
import jwt
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from rich.prompt import Prompt
class JWTEncoder():
    def crack_key_file(self,jwt_str,passwd,alg):
        """爆破jwt秘钥"""
        with open(passwd,"r",encoding="utf-8") as f:
            for line in f:
                key = line.strip()
                try:
                    jwt.decode(jwt_str,verify=True,key=key, algorithms=[alg])
                    OutPrintInfoSuc("JWT",f"found key successfully-->{key}")

                    break
                except (
                        jwt.exceptions.ExpiredSignatureError, jwt.exceptions.InvalidAudienceError,
                        jwt.exceptions.InvalidIssuedAtError,
                        jwt.exceptions.InvalidIssuedAtError, jwt.exceptions.ImmatureSignatureError
                ):
                    OutPrintInfoSuc("JWT", f"found key successfully-->{key}")
                    break
                except jwt.exceptions.InvalidSignatureError:
                    OutPrintInfo("JWT", f"try key -->{key}")
                    continue
            else:
                OutPrintInfo("JWT", "Done! no key was found")

    def crack_key(self,jwt_str,passwd,alg):
        """爆破jwt秘钥"""
        try:
            jwt.decode(jwt_str,verify=True,key=passwd, algorithms=[alg])
            OutPrintInfoSuc("JWT", f"found key successfully-->{passwd}")
        except (
                jwt.exceptions.ExpiredSignatureError, jwt.exceptions.InvalidAudienceError,
                jwt.exceptions.InvalidIssuedAtError,
                jwt.exceptions.InvalidIssuedAtError, jwt.exceptions.ImmatureSignatureError
        ):
            OutPrintInfoSuc("JWT", f"found key successfully-->{passwd}")
        except jwt.exceptions.InvalidSignatureError:
            OutPrintInfo("JWT", "Done! no key was found")



    def main(self,target):
        jwt_str = target["jwt"]
        alg = target["alg"]
        passwd = target["pwd"]
        passwdfile = target["pwdfile"]
        if passwd and passwdfile:
            OutPrintInfo("JWT", "检测到参数pwd与pwdfile同时存在\n[1]密钥检测\n[2]爆破检测")
            choose = Prompt.ask("[b red]选择模块",choices=["1","2"])
            if choose == "2":
                self.crack_key_file(jwt_str, passwdfile, alg)
            else:
                self.crack_key(jwt_str, passwd, alg)
            return
        if passwd:
            self.crack_key(jwt_str,passwd,alg)
        else:
            self.crack_key_file(jwt_str, passwdfile, alg)