import pandas as pd
import csv
import json
import math
import os
path_to_json = '/root/codesecure/'
json_files = [pos_json for pos_json in os.listdir(
    path_to_json) if pos_json.endswith('.csv')]
# print(json_files)
for i in json_files:
    if("results.csv" in i):
        file_name = "/root/codesecure/"+i
        df = pd.read_csv(file_name, encoding="ISO-8859-1")
        dict_ = list(df.T.to_dict().values())
        object_ = {"Vulnerabilities": dict_}
        out_name = "/root/codesecure/"+i+".json"
        out_name = out_name.replace(".csv", "")
        with open(out_name, 'w') as outfile:
            json.dump(object_, outfile, ensure_ascii=False, indent=2)
