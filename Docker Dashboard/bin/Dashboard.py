import requests
import pandas as pd


issue_severity=["MINOR","MAJOR","CRITICAL","BLOCKER"]
d3 = {}

for severity in issue_severity:
    d3[severity] = pd.DataFrame()
    url6 ="https://sonarcloud.io/api/issues/search?organization=test-my-first-integration&componentKeys=***********_vulnado&severities="+severity
    response6 = requests.request("GET", url6)
    data6 = response6.json()
    Slog = pd.json_normalize(data6['issues'])
    d3[severity] = Slog[['severity','component','line','message','type']]

sonarsouceSecurity=["sql-injection","command-injection","path-traversal-injection","ldap-injection","xpath-injection","rce","dos",
                    "ssrf","csrf","xss","log-injection","http-response-splitting","open-redirect","xxe","object-injection","weak-cryptography",
                    "auth","insecure-conf","encrypt-data","traceability","file-manipulation","others"]
sourceSecuritydf=pd.DataFrame()
d = {}

for sourceSecurity in sonarsouceSecurity:
    d[sourceSecurity] = pd.DataFrame()
    url10 ="https://sonarcloud.io/api/issues/search?organization=test-my-first-integration&componentKeys==***********_vulnado&sonarsourceSecurity="+sourceSecurity
    response10 = requests.request("GET", url10)
    data10 = response10.json()
    d[sourceSecurity] = pd.json_normalize(data10['issues'])

issue_types=["CODE_SMELL","BUG","VULNERABILITY"]
d1 = {}

for types in issue_types:
    d1[types] = pd.DataFrame()
    url11 ="https://sonarcloud.io/api/issues/search?organization=test-my-first-integration&componentKeys==***********_vulnado&types="+types
    response11 = requests.request("GET", url11)
    data11 = response11.json()
    d1[types] = pd.json_normalize(data11['issues'])


issue_tags =["security","convention"]
d2 = {}

for tags in issue_tags:
    d2[tags] = pd.DataFrame()
    url12 ="https://sonarcloud.io/api/issues/search?organization=test-my-first-integration&componentKeys==***********_vulnado&tags="+tags
    response12 = requests.request("GET", url12)
    data12 = response12.json()
    d2[tags] = pd.json_normalize(data12['issues'])

issue_status =["OPEN","CONFIRMED","REOPENED","RESOLVED","CLOSED"]
d4 = {}

for status in issue_status:
    d4[status] = pd.DataFrame()
    url13 ="https://sonarcloud.io/api/issues/search?organization=test-my-first-integration&componentKeys==***********_vulnado&statuses="+status
    response13 = requests.request("GET", url13)
    data13 = response13.json()
    d4[status] = pd.json_normalize(data13['issues'])

issue_sans =["insecure-interaction","risky-resource","porous-defenses"]
d5 = {}

for sans in issue_sans:
    d5[sans] = pd.DataFrame()
    url14 ="https://sonarcloud.io/api/issues/search?organization=test-my-first-integration&componentKeys==***********_vulnado&sansTop25="+sans
    response14 = requests.request("GET", url14)
    data14 = response14.json()
    d5[sans] = pd.json_normalize(data14['issues'])

issue_owasp = ["a1","a2","a3","a4","a5","a6","a7","a8","a9","a10"]
d6 = {}

for owasp in issue_owasp:
    d6[owasp] = pd.DataFrame()
    url15 ="https://sonarcloud.io/api/issues/search?organization=test-my-first-integration&componentKeys==***********_vulnado&owaspTop10="+owasp
    response15 = requests.request("GET", url15)
    data15 = response15.json()
    d6[owasp] = pd.json_normalize(data15['issues'])


issue_cwe =["unknown","493","546"]
d7 = {}

for cwe in issue_cwe:
    d7[cwe] = pd.DataFrame()
    url16 ="https://sonarcloud.io/api/issues/search?organization=test-my-first-integration&componentKeys==***********_vulnado&cwe="+cwe
    response16 = requests.request("GET", url16)
    data16 = response16.json()
    d7[cwe] = pd.json_normalize(data16['issues'])


data = [['MINOR', d3['MINOR'].shape[0]], ['MAJOR', d3['MAJOR'].shape[0]], ['CRITICAL', d3['CRITICAL'].shape[0]], ['BLOCKER', d3['BLOCKER'].shape[0]]]
data2 = [['CODE_SMELL', d1['CODE_SMELL'].shape[0]], ['BUG', d1['BUG'].shape[0]], ['VULNERABILITY', d1['VULNERABILITY'].shape[0]]]
# data3 = [['sql-injection', d['sql-injection'].shape[0]], ['command-injection', d['command-injection'].shape[0]], ['path-traversal-injection', d['path-traversal-injection'].shape[0]],
#          ['ldap-injection', d['ldap-injection'].shape[0]],['xpath-injection', d['xpath-injection'].shape[0]],['rce', d['rce'].shape[0]],['path-traversal-injection', d['path-traversal-injection'].shape[0]],
#          ['dos', d['dos'].shape[0]],['ssrf', d['ssrf'].shape[0]],['csrf', d['csrf'].shape[0]],['xss', d['xss'].shape[0]],
#          ['log-injection', d['log-injection'].shape[0]],'http-response-splitting', d['http-response-splitting'].shape[0],['open-redirect', d['open-redirect'].shape[0]],['xxe', d['xxe'].shape[0]],['object-injection', d['object-injection'].shape[0]],
#          ['auth', d['auth'].shape[0]],['insecure-conf', d['insecure-conf'].shape[0]],['weak-cryptography', d['weak-cryptography'].shape[0]],['insecure-conf', d['insecure-conf'].shape[0]],
#          ['encrypt-data', d['encrypt-data'].shape[0]],['file-manipulation', d['file-manipulation'].shape[0]],['others', d['others'].shape[0]]]
data4 = [['security', d2['security'].shape[0]], ['convention', d2['convention'].shape[0]]]
data5 = [['OPEN', d4['OPEN'].shape[0]], ['CONFIRMED', d4['CONFIRMED'].shape[0]], ['REOPENED', d4['REOPENED'].shape[0]], ['RESOLVED', d4['RESOLVED'].shape[0]], ['CLOSED', d4['CLOSED'].shape[0]]]
data6 = [['insecure-interaction', d5['insecure-interaction'].shape[0]], ['risky-resource', d5['risky-resource'].shape[0]], ['porous-defenses', d5['porous-defenses'].shape[0]]]
data7 = [['a1', d6['a1'].shape[0]], ['a2', d6['a2'].shape[0]], ['a3', d6['a3'].shape[0]], ['a4', d6['a4'].shape[0]], ['a5', d6['a5'].shape[0]],
         ['a6', d6['a6'].shape[0]], ['a7', d6['a7'].shape[0]], ['a8', d6['a8'].shape[0]], ['a9', d6['a9'].shape[0]], ['a10', d6['a10'].shape[0]]]
data8 = [['unknown', d7['unknown'].shape[0]], ['493', d7['493'].shape[0]], ['546', d7['546'].shape[0]]]

# Create the pandas DataFrame
df = pd.DataFrame(data, columns = ['Severity', 'No.of Issues'])
df2 = pd.DataFrame(data2, columns = ['Issue Types', 'No.of Issues'])
#df3 = pd.DataFrame(data3, columns = ['Sonar source Security', 'No.of Issues'])
df4 = pd.DataFrame(data4, columns = ['Issue Tags', 'No.of Issues'])
df5 = pd.DataFrame(data5, columns = ['Issue Status', 'No.of Issues'])
df6 = pd.DataFrame(data6, columns = ['Issue Sans', 'No.of Issues'])
df7 = pd.DataFrame(data7, columns = ['Issue owasp', 'No.of Issues'])
df8 = pd.DataFrame(data8, columns = ['Issue cwe', 'No.of Issues'])

import dash
import dash_html_components as html
import dash_core_components as dcc
import plotly.express as px
from dash.dependencies import Input, Output
import dash_table as dt



fig1 = px.pie(df, values='No.of Issues', names='Severity')
fig2 = px.bar(df2, y='No.of Issues', x='Issue Types', color='Issue Types')
#fig3 = px.bar(df3, y='No.of Issues', x='Sonar source Security', color='Sonar source Security')
fig4 = px.bar(df4, y='No.of Issues', x='Issue Tags', color='Issue Tags')
fig5 = px.pie(df5, values='No.of Issues', names='Issue Status', color='Issue Status')
fig6 = px.bar(df6, y='No.of Issues', x='Issue Sans', color='Issue Sans')
fig7 = px.bar(df7, y='No.of Issues', x='Issue owasp', color='Issue owasp')
fig8 = px.pie(df8, values='No.of Issues', names='Issue cwe')


external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

app = dash.Dash(__name__, external_stylesheets=external_stylesheets,suppress_callback_exceptions=True)

app.layout = html.Div([
    dcc.Tabs([
        dcc.Tab(label='Severity', children=[
            dcc.Graph(
                id='graph-1-tabs',
                figure= fig1
            ),
            dcc.Dropdown(
                id='dropdown1',
                value='MINOR',
                options=[{'value': x, 'label': x}
                         for x in issue_severity],
                searchable=False,
                clearable=False,
                persistence=True,
            ),
            dt.DataTable(
                id="dd1",
                columns=[{"name": i, "id": i} for i in ['key', 'rule', 'severity', 'component', 'project', 'line', 'hash']],
            ),
        ]),

        dcc.Tab(label='Issue Types', children=[
            dcc.Graph(
                id='graph-2-tabs',
                figure= fig2
            ),
            dcc.Dropdown(
                id='dropdown2',
                value='CODE_SMELL',
                options=[{'value': x, 'label': x}
                         for x in issue_types],
                searchable=False,
                clearable=False,
                persistence=True,
            ),
            dt.DataTable(
                id="dd2",
                columns=[{"name": i, "id": i} for i in ['key', 'rule', 'severity', 'component', 'project', 'line', 'hash']],
            ),
        ]),
        # dcc.Tab(label='Sonar Source Security', children=[
        #     dcc.Graph(
        #         id='graph-3-tabs',
        #         figure= fig3
        #     ),
        #     dcc.Dropdown(
        #         id='dropdown3',
        #         value='sql-injection',
        #         options=[{'value': x, 'label': x}
        #                  for x in sonarsouceSecurity],
        #         searchable=False,
        #         clearable=False,
        #     ),
        #     dt.DataTable(
        #         id="dd3",
        #         columns=[{"name": i, "id": i} for i in d['sql-injection'].columns],
        #     )
        # ]),
        dcc.Tab(label='Issue Tags', children=[
            dcc.Graph(
                id='graph-4-tabs',
                figure= fig4
            ),
            dcc.Dropdown(
                id='dropdown4',
                value='security',
                options=[{'value': x, 'label': x}
                         for x in issue_tags],
                searchable=False,
                clearable=False,
                persistence=True,
            ),
            dt.DataTable(
                id="dd4",
                columns=[{"name": i, "id": i} for i in ['key', 'rule', 'severity', 'component', 'project', 'line', 'hash']],
            ),
        ]),
        dcc.Tab(label='Issue Status', children=[
            dcc.Graph(
                id='graph-5-tabs',
                figure= fig5
            ),
            dcc.Dropdown(
                id='dropdown5',
                value='OPEN',
                options=[{'value': x, 'label': x}
                         for x in issue_status],
                searchable=False,
                clearable=False,
                persistence=True,
            ),
            dt.DataTable(
                id="dd5",
                columns=[{"name": i, "id": i} for i in ['key', 'rule', 'severity', 'component', 'project', 'line', 'hash']],
            ),
        ]),
        dcc.Tab(label='Issue Sans', children=[
            dcc.Graph(
                id='graph-6-tabs',
                figure= fig6
            ),
            dcc.Dropdown(
                id='dropdown6',
                value='insecure-interaction',
                options=[{'value': x, 'label': x}
                         for x in issue_sans],
                searchable=False,
                clearable=False,
                persistence=True,
            ),
            dt.DataTable(
                id="dd6",
                columns=[{"name": i, "id": i} for i in ['key', 'rule', 'severity', 'component', 'project', 'line', 'hash']],
            ),
        ]),
        dcc.Tab(label='Issue Owasp', children=[
            dcc.Graph(
                id='graph-7-tabs',
                figure= fig7
            ),
            dcc.Dropdown(
                id='dropdown7',
                value='a1',
                options=[{'value': x, 'label': x}
                         for x in issue_owasp],
                searchable=False,
                clearable=False,
                persistence=True,
            ),
            dt.DataTable(
                id="dd7",
                columns=[{"name": i, "id": i} for i in ['key', 'rule', 'severity', 'component', 'project', 'line', 'hash']],
            ),
        ]),
        dcc.Tab(label='Issue cwe', children=[
            dcc.Graph(
                id='graph-8-tabs',
                figure= fig8
            ),
            dcc.Dropdown(
                id='dropdown8',
                value='unknown',
                options=[{'value': x, 'label': x}
                         for x in issue_cwe],
                searchable=False,
                clearable=False,
                persistence=True,
            ),
            dt.DataTable(
                id="dd8",
                columns=[{"name": i, "id": i} for i in ['key', 'rule', 'severity', 'component', 'project', 'line', 'hash']],
            ),
        ]),
    ])
])

@app.callback(
    Output('dd1', 'data'),
    Input('dropdown1', 'value')
)
def update_output1(severity):
    return d3[severity].to_dict('records')

@app.callback(
    Output('dd2', 'data'),
    Input('dropdown2', 'value')
)
def update_output2(types):
    return d1[types].to_dict('records')

@app.callback(
    Output('dd3', 'data'),
    Input('dropdown3', 'value')
)
def update_output(security):
    return d[security].to_dict('records')

@app.callback(
    Output('dd4', 'data'),
    Input('dropdown4', 'value')
)
def update_output4(tags):
    return d2[tags].to_dict('records')


@app.callback(
    Output('dd5', 'data'),
    Input('dropdown5', 'value')
)
def update_output5(status):
    return d4[status].to_dict('records')


@app.callback(
    Output('dd6', 'data'),
    Input('dropdown6', 'value')
)
def update_output6(sans):
    return d5[sans].to_dict('records')


@app.callback(
    Output('dd7', 'data'),
    Input('dropdown7', 'value')
)
def update_output7(owasp):
    return d6[owasp].to_dict('records')


@app.callback(
    Output('dd8', 'data'),
    Input('dropdown8', 'value')
)
def update_output8(cwe):
    return d7[cwe].to_dict('records')

if __name__ == '__main__':
    app.run_server(host='0.0.0.0',port=8050,debug=True)
