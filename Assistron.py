from flask import Flask, request
import requests
import json
import logging

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
    print("-----------------------------")
    print(r.json().keys())
    print("-----------------------------")
    lastMessage = r.json()['items'][0]['text']
    if lastMessage == "Start":
        requests.post("https://webexapis.com/v1/messages", data = {'toPersonEmail' : email, 'text' : 'Por favor adjunta el archivo en formato CSV a procesar.'}, headers = headers)
    return "<p>Communication started</p>"