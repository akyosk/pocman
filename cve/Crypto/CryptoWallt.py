import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
class CryptoWalltScan:
    def run(self,i,key):
        try:
            url = f"https://confirmo.net/api/v3/balances?currency={i}"
            headers = {
                "accept": "application/json",
                "Authorization": f"Bearer {key}"
            }
            req = requests.get(url,headers=headers)
            if i in req.text:
                OutPrintInfoSuc(i,req.text)
            else:
                OutPrintInfo(i, "未查询到钱包余额")
        except Exception as e:
            OutPrintInfo(i,e)


    def main(self,target):
        j = ["BNB", "BTC", "ETH", "LTC", "MATIC", "SOL", "TRX", "USDC", "USDCE", "USDT", "USDTE", "AED", "ALL", "AMD",
             "ARS", "AUD", "AZN", "BDT", "BGN", "BHD", "BND", "BOB", "BRL", "BYN", "CAD", "CLP", "CNY", "COP", "CRC",
             "CVE", "CZK", "DKK", "DOP", "DZD", "EUR", "FKP", "GBP", "GEL", "GTQ", "HKD", "HRK", "HUF", "CHF", "IDR",
             "ILS", "INR", "ISK", "JMD", "JPY", "KGS", "KHR", "KWD", "KZT", "LTL", "MAD", "MDL", "MGA", "MKD", "MNT",
             "MOP", "MUR", "MXN", "MYR", "NGN", "NIO", "NOK", "NZD", "PEN", "PHP", "PLN", "PYG", "QAR", "RON", "RSD",
             "RUB", "SEK", "SGD", "THB", "TRY", "TWD", "UAH", "USD", "UYU", "VND", "XCD"]

        key = target["apikey"]
        OutPrintInfo("Crypto","开始查询钱包余额...")
        for i in j:
            self.run(i,key)
        OutPrintInfo("Crypto", "钱包余额查询结束")