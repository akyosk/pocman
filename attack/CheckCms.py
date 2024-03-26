#!/user/bin/env python3
# -*- coding: utf-8 -*-
from attack.ImpPoc import Shiro_Poc
def Check_Cms(cms,target,progress):
    if cms == "shiro":
        Shiro_Poc(target,progress)