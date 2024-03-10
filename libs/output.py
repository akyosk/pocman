#!/user/bin/env python3
# -*- coding: utf-8 -*-
def OutPutFile(filename,data):
    with open(f"./result/{filename}","a") as w:
        w.write(f"{data}\n")