import requests
import json
import datetime
import hashlib
import hmac
import base64


banner = """

Office 365 Defender For Endpoint to Azure Sentinel Analytics Workspace

Description:This code snippet sends Office 365 Defender for Endpoint Alerts to Sentinel Log analytics workspace in another Tenant

"""

print(banner)

#Access Token from the Defender Portal
Access_Token = "<ACCESS_TOKEN_HERE>"
# Azure Sentinel Workspace ID
customer_id = '<Log_Analytics_Workspace_ID>'
# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = "<Primary_Or_Seconday_Key_HERE>"
log_type = 'DefenderForEndpointAlerts'


Auth = 'Bearer '+Access_Token

# Change the sinceTimeUtc field to anydate you want
url = "https://wdatp-alertexporter-eu.securitycenter.windows.com/api/Alerts?sinceTimeUtc=2020-01-01T00:00:00.000"

payload={}
headers = {
  'Authorization': Auth
}

response = requests.request("GET", url, headers=headers, data=payload).json()

print("[+] Defender for Endpoint Alerts were received Successfully")

# Build the API signature
# build_signature and post_data functions full credit goes to https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('[+] Alert ',str(i),'was sent Successfully')
    else:
        print("Response code: {}".format(response.status_code))

for i in range(len(response)):

    ALERTTIME = response[i]["AlertTime"]
    DISPLAYNAME = response[i]["AlertTitle"]
    ALERTNAME = response[i]["AlertTitle"]
    ALERTSEVIRITY = response[i]["Severity"]
    DESCRIPTION = response[i]["Description"]
    PROVIDERNAME = "MDATP"
    VENDORNAME = "Microsoft"
    ALERTTYPE= "WindowsDefenderAtp"
    SOURCESYSTEM = "Detection"
    PRODUCTNAME = "Microsoft Defender Advanced Threat Protection"
    ALERTLINK = response[i]["LinkToMTP"]
    COMPROMISEDENTITY = response[i]["MachineName"]
    TACTICS = response[i]["Category"]
    CONNECTOR = "Customized Connector POC"

    json_data = [{
        "AlertTime": ALERTTIME,
        "DisplayName": DISPLAYNAME,
        "AlertName": ALERTNAME,
        "Severity": ALERTSEVIRITY,
        "Description": DESCRIPTION,
        "ProviderName": PROVIDERNAME,
        "VendorName": VENDORNAME,
        "AlertType": ALERTTYPE,
        "SourceSystem": SOURCESYSTEM,
        "ProductName": PRODUCTNAME,
        "AlertLink": ALERTLINK,
        "CompromisedEntity": COMPROMISEDENTITY,
        "Category": TACTICS,
        "Connector": CONNECTOR,
    }]
    
    body = json.dumps(json_data)
    
    post_data(customer_id, shared_key, body, log_type)
    

print("[+] All Defender for Endpoint Alerts were sent successfully to your Sentinel Log analytics Workspace")
