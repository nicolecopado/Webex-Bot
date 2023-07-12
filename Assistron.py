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
        print()
    try:
        fileURL = r.json()['items'][0]['files'][0]
        r2 = requests.get(fileURL, headers = headers)
        contentType = r2.headers['Content-Type']
        if contentType.endswith('csv'):
            requests.post("https://webexapis.com/v1/messages", data = {'toPersonEmail' : email, 'text' : 'Processing...'}, headers = headers)
            processCSV(r2.content)
        else:
            requests.post("https://webexapis.com/v1/messages", data = {'toPersonEmail' : email, 'text' : 'El archivo no está en formato CSV.'}, headers = headers)
    except KeyError:
        print()
    return "<p>Communication started</p>"

def processCSV(data):
    data = str(data, 'utf-8')
    df = pd.read_csv(StringIO(data))
    df = df.drop_duplicates(subset='IP address')
    df['Configured restconf'] = ["" for _ in range(df.shape[0])]
    df['Connectivity'] = ["" for _ in range(df.shape[0])]
    df['Memory Usage %'] = [None for _ in range(df.shape[0])]
    config_line = 'restconf'
    for index, row in df.iterrows():

        ip_address = row['IP address']

        device = {
                'device_type': 'cisco_ios',
                'ip': str(ip_address),
                'username': 'admin',
                'password': 'cisco!123',
                'secret': 'cisco!123'
                    }
        ip_address = row['IP address']

        try:
            connection = ConnectHandler(**device)
            output = connection.send_command('show run')

            if config_line in output:
                df.at[index, 'Configured restconf'] = "Restconf enabled"
                df.at[index, 'Connectivity'] = 'Reachable'
                output_list = output.split()
                versionStringIndex = output_list.index('version')
                OSVersion = output_list[versionStringIndex + 1]
                df.at[index, 'Version'] = OSVersion
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
                                df.at[index, 'Memory Usage %'] = (float(element['used-memory'])/float(element['total-memory']))*100
                    else:
                        print (f"Received response code: {response.status_code}")

                except Exception as e:
                    traceback_str = ''.join(traceback.format_tb(e.__traceback__))
                    print("Un error ocurrió")
                    print(traceback_str)
                
            else:
                df.at[index, 'Configured restconf'] = "No Restconf"
                df.at[index, 'Connectivity'] = 'Reachable'

        except Exception as e:
            df.at[index, 'Configured restconf'] = "No Restconf"
            df.at[index, 'Connectivity'] = 'Unreachable'
        finally:
            connection.disconnect()
        df.fillna('N/A')
        csv_file = 'interns_challenge_new.csv'
        df.to_csv(csv_file, index = False)   
        # if row['OS type']== 'IOS-XE':
        #     device = {
        #         'device_type': 'cisco_ios',
        #         'ip': str(ip_address),
        #         'username': 'admin',
        #         'password': 'cisco!123',
        #         'secret': 'cisco!123'
        #             }
        #     try:
        #         connection = ConnectHandler(**device)
        #         output = connection.send_command('show run')
        #         if config_line in output:
        #             df.at[index, 'Configured restconf'] = "Restconf enabled"
        #         else:
        #             df.at[index, 'Configured restconf'] = "No Restconf"
        #         connection.disconnect()
        #     except Exception as e:
        #         print(f"Failed to retrieve info from {ip_address}: {str(e)}")
        # elif row['OS type']== 'IOS':
        #     df.at[index, 'Configured restconf'] = "Not supported"
        # else:
        #     df.at[index, 'Configured restconf'] = "Unreachable/Unknown"