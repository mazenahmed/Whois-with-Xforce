import requests
from base64 import b64encode
import csv
from pyfiglet import figlet_format
import time
from getpass import getpass


def whois(host):
    '''
    this method communicates with IBM Xforce API
    and reterive Whois DB
    '''
    
    headers = {'content-type': 'application/json'}
    url = 'https://api.xforce.ibmcloud.com/whois/' + str(host)
    headers = {'Accept':'application/json', 'Authorization': 'Basic ' + str(token)}
    response = requests.get(url,headers=headers)
    if(response.status_code == 200):
        return {1:response.json()}
    elif (response.status_code == 400):
        return({0:'Invalid Host.'})
        
    elif (response.status_code == 401):
        return({0:'Unauthorized.'})
    
    elif (response.status_code == 402):
        return({0:'Quota has been Exceeded.'})
    
print(figlet_format("GETTING INFO"))
key= getpass(prompt='API Key: ')
password= getpass(prompt='Password: ')
token = b64encode(str.encode(str(key) + ":" + str(password))).decode()

print(figlet_format("REQUESTING WHOIS INFO"))
with open('hosts.csv', mode='r') as csv_host:
    host_read = csv.reader(csv_host,delimiter=',')
    output=open("results.csv","w+")
    filewriter = csv.writer(output)
    filewriter.writerow(['IP','Organization','Country','Name'])
    for row in host_read:
        for column in row:
            if column:
                print("Querying {0}".format(column))
                resp = whois(column)
                if list(resp.keys())[0] == 0:
                    filewriter.writerow([column,resp[0],resp[0],resp[0]])
                    print(resp[0])

                elif list(resp.keys())[0] == 1:
                    
                    if "sub" in resp[1]["extended"]:
                        
                        resp= resp[1]["extended"]["sub"][-1]["contact"]
                        if "name" in list(resp[0].keys()):
                            filewriter.writerow([column,resp[0]['organization'],resp[0]['country'],resp[0]['name']])
                        else:
                            filewriter.writerow([column,resp[0]['organization'],resp[0]['country'],' '])
                    else:
                        resp= resp[1]["extended"]["contact"]
                        if "name" in list(resp[0].keys()):
                            filewriter.writerow([column,resp[0]['organization'],resp[0]['country'],resp[0]['name']])
                        else:
                            filewriter.writerow([column,resp[0]['organization'],resp[0]['country'],' '])
                time.sleep(1)

    output.close()
print(figlet_format("SEE YA"))
print("Created By Mazen A. Gaballah")
