
import json
import os
import requests
import zipfile

ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36'
headers = {'user-agent': ua}
base_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip'
def download_json_feed():
    r = requests.get(base_url, headers=headers, allow_redirects=True)
    file_name = 'nvdcve-1.1-recent.json.zip'
    open(file_name, 'wb').write(r.content)
    with zipfile.ZipFile(file_name, 'r') as zip_ref:
        zip_ref.extractall()
def get_all_datafile():
    json_list = []
    for dirname, folder, files in os.walk("."):
        for filename in files:
            if filename.endswith(".json"):
                json_list.append(filename)
    return json_list

download_json_feed()
json_filelist = get_all_datafile()

for json_file in json_filelist:
    # print(json_file)
    print('Json filename:', json_file)
    with open(json_file, encoding='utf-8') as json_content:
        json_data = json.load(json_content)
    # print(json_data)
cve_timestamp = json_data["CVE_data_timestamp"]
print('CVE Feed Timestamp:', json_data["CVE_data_timestamp"])

for items in json_data["CVE_Items"]:
    cve_info = items["cve"]
    cve_published_date = items["publishedDate"]
    cve_lastmodified_date = items["lastModifiedDate"]
    # print(cve_info)
    cve_id = cve_info["CVE_data_meta"]["ID"]
    print('\n')
    print('cve_id:', cve_id)
    # print('\n')
    print('cve_published date:', cve_published_date)
    print('cve_lastmodified date:', cve_lastmodified_date)

    for cve_value in cve_info["description"]["description_data"]:
        cve_description = cve_value["value"]
        cve_name = cve_value[]
        print('cve_description:',cve_description)
        # cve_references_url = cve_references["reference_data"]
        # cve_references_name = cve_info["references"]["reference_data"]["name"]
        # cve_references_tags = cve_info["references"]["reference_data"]["tags"]
        # print(cve_references_name)
        # print(cve_references_tags)
        # print(cve_references_url)

#
#
# def load(json_file):
#     print(json_file)
#     uaf_list = []
#     with open(json_file) as json_data:
#         data = json.load(json_data)
#     # for key in data.keys():
#     #    print(key)
#     for items in data["CVE_Items"]:
#         cve_info = items["cve"]
#         # print(cve_info["CVE_data_meta"]["ID"])
#         cve_id = cve_info["CVE_data_meta"]["ID"]
#
#         uaf_flag = False
#         # check whether it is UAF
#         for cwe in cve_info["problemtype"]["problemtype_data"]:
#             for dp in cwe["description"]:
#                 if dp["value"] == "CWE-416" or dp["value"] == "CWE-415":
#                     uaf_flag = True
#                     break
#
#         if not uaf_flag:
#             continue
#
#         kernel_flag = False
#         # check whether it is Linux Kernel Vulnerability
#         for vendor in cve_info["affects"]["vendor"]["vendor_data"]:
#             if vendor["vendor_name"] != "linux":
#                 continue
#             for product in vendor["product"]["product_data"]:
#                 # print(product["product_name"])
#                 if product["product_name"] == "linux_kernel":
#                     kernel_flag = True
#         if not kernel_flag:
#             continue
#
#         uaf_list.append(cve_id)
#
#     print len(uaf_list)
#     print uaf_list
#
#
# if __name__ == "__main__":
#     json_files = get_all_datafile()
#     # json_files = ["nvdcve-1.0-2017.json"]
#     # print(json_files)
#     for json_file in json_files:
#         load(json_file)
