from flask import Flask, request
import requests
from requests.auth import HTTPBasicAuth
import json
import logging
import pandas as pd
from io import StringIO
import netmiko
from netmiko import ConnectHandler
import re
import traceback
from requests_toolbelt.multipart.encoder import MultipartEncoder
import copy
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p></p>"

@app.route("/interaction-started-webhook", methods=['POST'])
def start_interaction():
    data = request.get_data()
    email = json.loads(data)['data']['personEmail']
    headers = {'Authorization' : 'Bearer MTBmZmU0NWQtYmYxMi00ZGJjLTk2OTUtZDEzZjUxYmE3MjRiYzI1ZjlkYzYtMjQx_PF84_1eb65fdf-9643-417f-9974-ad72cae0e10f'}
    r = requests.get("https://webexapis.com/v1/messages/direct", params={'personEmail' : f'{email}'}, headers = headers)
    try:
        lastMessage = r.json()['items'][0]['text']
        if lastMessage == "Start":
            requests.post("https://webexapis.com/v1/messages", data = {'toPersonEmail' : email, 'text' : 'Por favor adjunta el archivo en formato CSV a procesar.'}, headers = headers)
    except:
        pass
    try:
        fileURL = r.json()['items'][0]['files'][0]
        r2 = requests.get(fileURL, headers = headers)
        contentType = r2.headers['Content-Type']
        if contentType.endswith('csv'):
            requests.post("https://webexapis.com/v1/messages", data = {'toPersonEmail' : email, 'text' : 'Processing...'}, headers = headers)
            text = r2.headers['content-disposition']
            match = re.search(r'"(.+?)(?:\.\w{3})"', text)
            csv_filename = match.group(1)
            processCSV(r2.content, csv_filename)

            m = MultipartEncoder({
                      'toPersonEmail' : email,
                      'text': 'Here is your processed .csv file.',
                      'files': (csv_filename + "_Processed.csv", open(csv_filename + "_Processed.csv", 'rb'),
                      'multipart/form-data')
                                })
            headersTemp = copy.deepcopy(headers)
            headersTemp['Content-Type'] = m.content_type
            r = requests.post('https://webexapis.com/v1/messages', data=m,
                  headers=headersTemp)

            m = MultipartEncoder({
                      'toPersonEmail' : email,
                      'text': 'Here is your network report.',
                      'files': (csv_filename + "_Report.pdf", open(csv_filename + "_Report.pdf", 'rb'),
                      'multipart/form-data')
                                })
            headersTemp = copy.deepcopy(headers)
            headersTemp['Content-Type'] = m.content_type
            r = requests.post('https://webexapis.com/v1/messages', data=m,
                  headers=headersTemp)


        else:
            requests.post("https://webexapis.com/v1/messages", data = {'toPersonEmail' : email, 'text' : 'El archivo no está en formato CSV.'}, headers = headers)
    except KeyError:
        pass
    return "<p>Communication started</p>"

def processCSV(data, filename):
    data = str(data, 'utf-8')
    df = pd.read_csv(StringIO(data))
    df = df.drop_duplicates(subset='IP address')
    df['Configured restconf'] = ["" for _ in range(df.shape[0])]
    df['Connectivity'] = ["" for _ in range(df.shape[0])]
    df['Memory Usage %'] = [None for _ in range(df.shape[0])]
    df['Encrypted Password'] = [None for _ in range(df.shape[0])]
    df['Potential_bugs'] = None
    df['Serial'] = None
    df['PSIRT'] = ''
    df['CRITICAL_PSIRT'] = ''
    df['[ALERT] Critical Memory Usage'] = None
    config_line = 'restconf'
    token = ""
    url = 'https://id.cisco.com/oauth2/default/v1/token'
    data = {
            'client_id': '63ed3gpqg5jbrrmbdch6zd4d',
            'client_secret': 'fTrzZVVTAMP9AdcRTXPvbSyS',
            'grant_type': 'client_credentials',
            }
    response = requests.post(url, data=data)
        # Validate we are getting a 200 status code
    if response.status_code == 200:
        # Parse the response in json format
        token = response.json().get('access_token')
    else:
        print(f'Request failed with status code {response.status_code}')

    for index, row in df.iterrows():

        ip_address = row['IP address']

        device = {
                'device_type': 'cisco_ios',
                'ip': str(ip_address),
                'username': 'admin',
                'password': 'cisco!123',
                'secret': 'cisco!123'
                    }
                    
        try:
            connection = ConnectHandler(**device)
            output = connection.send_command('show run')

            if config_line in output:
                df.at[index, 'Configured restconf'] = "Restconf enabled"
                df.at[index, 'Connectivity'] = 'Reachable'
                output_list = output.split()
                versionStringIndex = output_list.index('version')
                OSVersion = output_list[versionStringIndex + 1]
                df.at[index, 'Version'] = str(OSVersion) + ".1"
                if 'secret' in output:
                    df.at[index, 'Encrypted Password'] = True 
                else:
                    df.at[index, 'Encrypted Password'] = False
                try:
                    url_mem = f"https://{ip_address}/restconf/data/Cisco-IOS-XE-memory-oper:memory-statistics"
                    headers = {'Accept': 'application/yang-data+json'}
                    response = requests.get(url_mem, headers=headers, verify=False, auth=HTTPBasicAuth(device['username'], device['password']))
                    if response.status_code == 200:
                        response = response.json()
                        # Parse the response to only get the Processor total and used memory information
                        memory_statistics = response['Cisco-IOS-XE-memory-oper:memory-statistics']['memory-statistic']
                        for element in memory_statistics:   
                            if element['name'] == 'Processor':
                                memoryUsage = (float(element['used-memory'])/float(element['total-memory']))*100
                                df.at[index, 'Memory Usage %'] = memoryUsage
                                if memoryUsage > 90.0:
                                    df.at[index, '[ALERT] Critical Memory Usage'] = True
                                else:
                                    df.at[index, '[ALERT] Critical Memory Usage'] = False
                    else:   
                        print (f"Received response code: {response.status_code}")

                except Exception as e:
                    traceback_str = ''.join(traceback.format_tb(e.__traceback__))
                    print("Un error ocurrió")
                    print(traceback_str)

                url_lic = f"https://{ip_address}/restconf/data/Cisco-IOS-XE-native:native/license/udi"
                response = requests.get(url_lic, headers=headers, verify=False, auth=HTTPBasicAuth(device['username'], device['password']))
                
                if response.status_code == 200:
                    response = response.json()
                    sn_value = response['Cisco-IOS-XE-native:udi']['sn']
                    pid_value = response['Cisco-IOS-XE-native:udi']['pid']
                    df.at[index, 'Serial'] = sn_value
                    df.at[index, 'PID'] = pid_value

                else:
                    print (f"Received response code: {response.status_code}")
                    df.at[index, 'Serial'] = "Can't retrieve SN"
                    df.at[index, 'PID'] = "Can't retrieve PID"

                device_id = row['PID']
                if device_id:
                    try:
                        headers = {
                        'Authorization': f'Bearer {token}',
                                }
                        url = f"https://apix.cisco.com/bug/v3.0/bugs/products/product_id/{device_id}?page_index=1&modified_date=5"
                        response = requests.get(url, headers=headers)

                        # Validate the status code as 200
                        if response.status_code == 200:
                            # Parse the response in json format
                            response_data = response.json()
                            # List comprehension in python: https://realpython.com/list-comprehension-python/
                            bug_id = [bug['bug_id'] for bug in response_data['bugs']]
                            # Update the bug_id information in the proper column/row
                            df.loc[index, 'Potential_bugs'] = str(bug_id)
                        else:
                            print(f'Request failed with status code {response.status_code}')
                            df.loc[index, 'Potential_bugs'] = 'Wrong API access'

                    except Exception as e:
                        print(f"Failed to retrieve info from {device_id}: {str(e)}")

                version = row['Version']
                if version:
                    try:
                        url = f"https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version={version}"
                        response = requests.get(url, headers=headers)
                        
                        # Validate the status code as 200
                        if response.status_code == 200:
                            # Parse the response in json format
                            response_data = (response.json())
                            
                            advisoryId = list()
                            criticalAdvisoryId = list()
                            # List comprehension in python: https://realpython.com/list-comprehension-python/
                            for bug in response_data['advisories']:
                                advisoryId.append(bug['advisoryId'])
                                if(float(bug['cvssBaseScore']) >= 7.0):
                                    criticalAdvisoryId.append(bug['advisoryId'])
                            # Update the bug_id information in the proper column/row
                            df.at[index, 'PSIRT'] = advisoryId
                            df.at[index, 'CRITICAL_PSIRT'] = criticalAdvisoryId

                        else:
                            print(f'Request failed with status code {response.status_code}')
                            df.at[index, 'PSIRT'] = 'Wrong API access'
                    except Exception as e:
                        print(f"Failed to retrieve info from {version}: {str(e)}")
                            
            else:
                df.at[index, 'Configured restconf'] = "No Restconf"
                df.at[index, 'Connectivity'] = 'Reachable'

            connection.disconnect()

        except Exception as e:
            df.at[index, 'Configured restconf'] = "No Restconf"
            df.at[index, 'Connectivity'] = 'Unreachable'
            
        df.fillna(value="N/A", inplace=True)
        df.to_csv(filename + "_Processed.csv" , index = False)
        create_report(df, filename)

def create_report(dataF, filename):
    # Define the document
    doc = SimpleDocTemplate(filename + "_Report.pdf", pagesize=letter)

    # Define styles
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        spaceAfter=10
    )

    # Create the content flowables
    flowables = []

    # Insert logo at the header
    logo = Image("cisco_logo.png")
    logo.drawWidth = 80
    logo.drawHeight = 65
    flowables.append(logo)
    device = "PID & IP address"

    # Add the report title
    flowables.append(Paragraph("Assistron Report", title_style))

    # Add subtitle
    for col_num, row in dataF.iterrows():
        flowables.append(Paragraph(f"PID: {row['PID']} & IP address: {row['IP address']}", subtitle_style))
        flowables.append(Paragraph(f"IP Address: {row['IP address']}", styles["Normal"]))
        flowables.append(Paragraph(f"Version: {row['Version']}", styles["Normal"]))
        flowables.append(Paragraph(f"Configured Restconfig: {row['Configured restconf']}", styles["Normal"]))
        flowables.append(Paragraph(f"Conectivity: {row['Connectivity']}", styles["Normal"]))
        flowables.append(Paragraph(f"Memory Usage: {row['Memory Usage %']}", styles["Normal"]))
        flowables.append(Paragraph(f"Encrypted Password: {row['Encrypted Password']}", styles["Normal"]))
        flowables.append(Paragraph(f"Potential Bugs: {row['Potential_bugs']}", styles["Normal"]))
        flowables.append(Paragraph(f"PSIRT: {row['PSIRT']}", styles["Normal"]))
        flowables.append(Paragraph(f"Critical PSIRT: {row['CRITICAL_PSIRT']}", styles["Normal"]))
        flowables.append(Paragraph(f"[Alert] Critical Memory: {row['Connectivity']}", styles["Normal"]))
        flowables.append(Paragraph("", subtitle_style))

    # Build the document
    doc.build(flowables)
           