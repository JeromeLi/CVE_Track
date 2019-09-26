#!/usr/bin/env python

import json
import os

def get_all_datafile():
    json_list = []
    for dirname,folder,files in os.walk("."):
        for filename in files:
            if filename.endswith(".json"):
                json_list.append(filename)
    return json_list

def load(json_file):
    print(json_file)
    uaf_list = []
    with open(json_file) as json_data:  
        data = json.load(json_data)
    #for key in data.keys():
    #    print(key)
    for items in data["CVE_Items"]:
        cve_info = items["cve"]
        #print(cve_info["CVE_data_meta"]["ID"])
        cve_id = cve_info["CVE_data_meta"]["ID"]

        uaf_flag = False
        # check whether it is UAF 
        for cwe in cve_info["problemtype"]["problemtype_data"]:
            for dp in cwe["description"]:
                if dp["value"] == "CWE-416" or dp["value"] == "CWE-415" :
                    uaf_flag = True
                    break

        if not uaf_flag:
            continue

        kernel_flag = False
        # check whether it is Linux Kernel Vulnerability
        for vendor in cve_info["affects"]["vendor"]["vendor_data"]:
            if vendor["vendor_name"] != "linux":
                continue
            for product in vendor["product"]["product_data"]:
                #print(product["product_name"])
                if product["product_name"] == "linux_kernel":
                    kernel_flag = True
        if not kernel_flag:
            continue

        uaf_list.append(cve_id)

    # print len(uaf_list)
    # print uaf_list

if __name__ == "__main__":
    json_files = get_all_datafile()
    #json_files = ["nvdcve-1.0-2017.json"]
    #print(json_files)
    for json_file in json_files:
        load(json_file)
