#!/user/bin/env python3
# -*- coding: utf-8 -*-
import datetime
def Time():
    now = datetime.datetime.now()
    nowTime = now.strftime("%H:%M:%S")
    return nowTime