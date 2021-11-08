#!/usr/bin/env python
# coding: utf-8
# # Code to Get all the repositories in the organization

import requests
import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from numpy.random import randn
import pdfkit
issue_severity=["MINOR","MAJOR","CRITICAL","BLOCKER"]

d3 = {}
dff1=pd.DataFrame()

for severity in issue_severity:
    d3[severity] = pd.DataFrame()
    url6 ="https://sonarcloud.io/api/issues/search?organization=<organization>&componentKeys=<component-key>&severities="+severity
    response6 = requests.request("GET", url6)
    data6 = response6.json()
    Slog = pd.json_normalize(data6['issues'])
    d3[severity] = Slog[['severity','component','line','message','type']]
    dff1= dff1.append(d3[severity])

sonarsouceSecurity=["sql-injection","command-injection","path-traversal-injection","ldap-injection","xpath-injection","rce","dos",
                    "ssrf","csrf","xss","log-injection","http-response-splitting","open-redirect","xxe","object-injection","weak-cryptography",
                    "auth","insecure-conf","encrypt-data","traceability","file-manipulation","others"]
sourceSecuritydf=pd.DataFrame()
d = {}
dff2=pd.DataFrame()

for sourceSecurity in sonarsouceSecurity:
    d[sourceSecurity] = pd.DataFrame()
    url10 ="https://sonarcloud.io/api/issues/search?organization=<organization>&componentKeys=<component-key>&sonarsourceSecurity="+sourceSecurity
    response10 = requests.request("GET", url10)
    data10 = response10.json()
    d[sourceSecurity] = pd.json_normalize(data10['issues'])
    dff2= dff2.append(d[sourceSecurity])

issue_types=["CODE_SMELL","BUG","VULNERABILITY"]

d1 = {}
dff3=pd.DataFrame()

for types in issue_types:
    d1[types] = pd.DataFrame()
    url11 ="https://sonarcloud.io/api/issues/search?organization=<organization>&componentKeys=<component-key>&types="+types
    response11 = requests.request("GET", url11)
    data11 = response11.json()
    d1[types] = pd.json_normalize(data11['issues'])
    dff3= dff3.append(d1[types])
issue_tags =["security","convention"]

d2 = {}
dff4=pd.DataFrame()
for tags in issue_tags:
    d2[tags] = pd.DataFrame()
    url12 ="https://sonarcloud.io/api/issues/search?organization=<organization>&componentKeys=<component-key>&tags="+tags
    response12 = requests.request("GET", url12)
    data12 = response12.json()
    d2[tags] = pd.json_normalize(data12['issues'])
    dff4= dff4.append(d2[tags])

issue_status =["OPEN","CONFIRMED","REOPENED","RESOLVED","CLOSED"]
d4 = {}
dff5=pd.DataFrame()

for status in issue_status:
    d4[status] = pd.DataFrame()
    url13 ="https://sonarcloud.io/api/issues/search?organization=<organization>&componentKeys=<component-key>&statuses="+status
    response13 = requests.request("GET", url13)
    data13 = response13.json()
    d4[status] = pd.json_normalize(data13['issues'])
    dff5= dff5.append(d4[status])
issue_sans =["insecure-interaction","risky-resource","porous-defenses"]

d5 = {}
dff6=pd.DataFrame()
for sans in issue_sans:
    d5[sans] = pd.DataFrame()
    url14 ="https://sonarcloud.io/api/issues/search?organization=<organization>&componentKeys=<component-key>&sansTop25="+sans
    response14 = requests.request("GET", url14)
    data14 = response14.json()
    d5[sans] = pd.json_normalize(data14['issues'])
    dff6= dff6.append(d5[sans])
issue_owasp = ["a1","a2","a3","a4","a5","a6","a7","a8","a9","a10"]

d6 = {}
dff7=pd.DataFrame()
for owasp in issue_owasp:
    d6[owasp] = pd.DataFrame()
    url15 ="https://sonarcloud.io/api/issues/search?organization=<organization>&componentKeys=<component-key>&owaspTop10="+owasp
    response15 = requests.request("GET", url15)
    data15 = response15.json()
    d6[owasp] = pd.json_normalize(data15['issues'])
    dff7= dff7.append(d6[owasp])

issue_cwe =["unknown","493","546"]
d7 = {}
dff8=pd.DataFrame()

for cwe in issue_cwe:
    d7[cwe] = pd.DataFrame()
    url16 ="https://sonarcloud.io/api/issues/search?organization=<organization>&componentKeys=<component-key>&cwe="+cwe
    response16 = requests.request("GET", url16)
    data16 = response16.json()
    d7[cwe] = pd.json_normalize(data16['issues'])
    dff8= dff8.append(d7[cwe])
fluid = pd.DataFrame(pd.read_csv (r'/root/codesecure/results.csv', sep = ",", header=0, index_col = False))
fluid.to_json (r'/root/codesecure/results.json',orient = "records", date_format = "epoch", double_precision = 10, force_ascii = True, date_unit = "ms", default_handler = None)
with open('/root/codesecure/results.json') as f:
    fluidLog = json.load(f)
flog = pd.json_normalize(fluidLog)
flog = flog[["what","where","title","snippet"]]
flog.insert(loc=0, column='severity', value='MAJOR')

data = [['MINOR', d3['MINOR'].shape[0]], ['MAJOR', d3['MAJOR'].shape[0]], ['CRITICAL', d3['CRITICAL'].shape[0]], ['BLOCKER', d3['BLOCKER'].shape[0]]]
data1 = pd.DataFrame(data, columns = ['Issues', 'No.of Issues'])

with open("a.html", 'w') as _file:
    _file.write(data1.to_html()+ "\n\n" +flog.to_html()+ "\n\n" +dff1.to_html() + "\n\n" + dff2.to_html()+ "\n\n" + dff3.to_html()+ "\n\n" + dff4.to_html()
        + "\n\n" + dff5.to_html()+ "\n\n" + dff6.to_html()+ "\n\n" + dff7.to_html()+ "\n\n" + dff8.to_html())

pdfkit.from_file("a.html", "report.pdf")