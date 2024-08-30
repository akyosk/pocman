from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc

class BT_DecodePassWord:
    def main(self, target):
        div_str = target['btdiv']
        password_str = target['password']
        key = "Z2B87NEAS2BkxTrh"
        iv = "WwadH66EGWpeeTT6"
        try:
            byte_div = b64decode(div_str)
            aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
            decrypted_data = aes.decrypt(byte_div)
            dec_div = unpad(decrypted_data, AES.block_size)
            bt_div = dec_div.decode('utf-8')
            OutPrintInfoSuc("BT",f"BT-DIV: {bt_div}")


            key = "3P+_lN3+jPW6Kgt#"
            iv = bt_div
            byte_bt = b64decode(password_str)
            aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
            decrypted_data = aes.decrypt(byte_bt)
            dec_bt = unpad(decrypted_data, AES.block_size)
            OutPrintInfoSuc("BT",f"Password: {dec_bt}")

        except Exception as e:
            OutPrintInfo("BT",f"解密出错: {e}")