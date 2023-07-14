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
    rowNumber = df.shape[0]
    df['Configured restconf'] = ["" for _ in range(rowNumber)]
    df['Connectivity'] = ["" for _ in range(rowNumber)]
    df['Memory Usage %'] = [None for _ in range(rowNumber)]
    df['Encrypted Password'] = [None for _ in range(rowNumber)]
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
        print("Your access token is: " + str(token))
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
                df.at[index, 'Version'] = str(OSVersion) + ".1"
                if 'secret' in output:
                    df.at[index, 'Encrypted Password'] = True 
                else:
                    df.at[index, 'Encrypted Password'] = False
                # try:
                #     url_mem = f"https://{ip_address}/restconf/data/Cisco-IOS-XE-memory-oper:memory-statistics"
                #     headers = {'Accept': 'application/yang-data+json'}
                #     response = requests.get(url_mem, headers=headers, verify=False, auth=HTTPBasicAuth(device['username'], device['password']))
                #     if response.status_code == 200:
                #         response = response.json()
                #         # Parse the response to only get the Processor total and used memory information
                #         memory_statistics = response['Cisco-IOS-XE-memory-oper:memory-statistics']['memory-statistic']
                #         for element in memory_statistics:   
                #             if element['name'] == 'Processor':
                #                 usagePercentage = (float(element['used-memory'])/float(element['total-memory']))*100
                #                 if usagePercentage > 90.0:
                #                     mensaje = "El uso de memoria del dispositivo con PID " + df.loc[index, 'PID'] 
                #                     requests.post("https://webexapis.com/v1/messages", data = {'toPersonEmail' : email, 'text' : 'El uso de memoria del dispositivo {df.loc[]} '}, headers = headers)
                #                 df.at[index, 'Memory Usage %'] = usagePercentage
                #     else:
                #         print (f"Received response code: {response.status_code}")

                # except Exception as e:
                #     traceback_str = ''.join(traceback.format_tb(e.__traceback__))
                #     print("Un error ocurrió")
                #     print(traceback_str)

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
                                usagePercentage = (float(element['used-memory'])/float(element['total-memory']))*100
                                if usagePercentage > 90.0:
                                    if rowNumber <= 10:
                                        mensaje = "El uso de memoria del dispositivo con PID " + df.loc[index, 'PID'] + " e IP " + df.loc[index, 'IP address'] + " excede el 90% y puede representar un problema."
                                        requests.post("https://webexapis.com/v1/messages", data = {'toPersonEmail' : email, 'text' : mensaje}, headers = headers)
                                    df.at[index, '[ALERT] Critical Memory Usage'] = True
                                df.at[index, 'Memory Usage %'] = usagePercentage
                    else:
                        print (f"Received response code: {response.status_code}")

                except Exception as e:
                    traceback_str = ''.join(traceback.format_tb(e.__traceback__))
                    print("Un error ocurrió")
                    print(traceback_str)

                version = row['Version']
                if version:
                    try:
                        print("-------------------")
                        print(version)
                        print(headers)
                        print("--------------------------")
                        url = f"https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version={version}"
                        response = requests.get(url, headers=headers)
                        
                        # Validate the status code as 200
                        if response.status_code == 200:
                            # Parse the response in json format
                            response_data = (response.json())
                            #Print the response_data so you can see how to filter it to just keep the bug ID
                            print (response_data)
                            
                            
                            # List comprehension in python: https://realpython.com/list-comprehension-python/
                            advisoryId = [bug['advisoryId'] for bug in response_data['advisories']]
                            print(response_data['advisories'])
                            # Update the bug_id information in the proper column/row
                            df.at[index, 'PSIRT'] = advisoryId
                            

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
        csv_file = 'interns_challenge_new.csv'
        df.to_csv(csv_file, index = False)   