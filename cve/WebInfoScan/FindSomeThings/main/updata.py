
def logging(info):
    for i in range(10):
        with open('./result/findSomeThingReport.txt', 'a+') as f:
            print(info,file = f)