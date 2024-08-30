import rsa
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from rich.prompt import Prompt
class Encrypt(object):
    def __init__(self):
        self.e = None
        self.m = None

    def encrypt(self, message):
        mm = int(self.m, 16)
        ee = int(self.e, 16)
        rsa_pubkey = rsa.PublicKey(mm, ee)
        crypto = self._encrypt(message.encode(), rsa_pubkey)
        return crypto.hex()

    def _pad_for_encryption(self, message, target_length):
        message = message[::-1]
        max_msglength = target_length - 11
        msglength = len(message)

        padding = b''
        padding_length = target_length - msglength - 3

        for i in range(padding_length):
            padding += b'\x00'

        return b''.join([b'\x00\x00', padding, b'\x00', message])

    def _encrypt(self, message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = self._pad_for_encryption(message, keylength)

        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)

        return block


    def main(self,target):
        self.m = target['m']
        self.e = target['e']
        rsapass = target['foundpwd']
        o = target['outfile']
        pwdfile = target['encodefile']
        if rsapass == False:
            OutPrintInfo("RSA","开始生成加密字典...")
            with open(f"result/{o}", "a") as f:
                try:
                    for message in open(pwdfile,'r'):
                        f.write(self.encrypt(message[::-1].strip())+"\n")
                except Exception as e:
                    OutPrintInfo("RSA",e)
                    return
            OutPrintInfoSuc("RSA", f"加密字典生成成功,保存于/result/{o}")
            OutPrintInfo("RSA", "生成结束")
            return
        rpass = Prompt.ask("[b yellow]输入需要查询的RSA加密文本")
        OutPrintInfo("RSA", "开始查询...")
        try:
            for message in open(pwdfile, 'r'):
                if self.encrypt(message[::-1].strip()) == rpass:
                    OutPrintInfoSuc("RSA",message.strip())
                    break

        except Exception as e:
            OutPrintInfo("RSA", e)
            return
        OutPrintInfo("RSA", "查询结束")

