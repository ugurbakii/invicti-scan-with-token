#python3 createscan.py --target_uri "https://domain" --profile_name "apimobile" --file_type "swagger" --file_url_or_path "https://domain/accounts/v3/api-docs"

import requests, json, argparse, os
from base64 import b64encode
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning
import requests

requests.urllib3.disable_warnings()     
# constants
ENV_VARS = os.environ
URL = ENV_VARS.get("INVICTI_URL", "w")
USER_ID = ENV_VARS.get("INVICTI_USER_ID", "x")
TOKEN = ENV_VARS.get("INVICTI_TOKEN", "y")
POLICY_ID = ENV_VARS.get("INVICTI_POLICY_ID", "z")
REPORT_POLICY_ID = ENV_VARS.get("INVICTI_REPORT_POLICY_ID", "t")

# variables
parser = argparse.ArgumentParser(description="Create Invicti Scan")
parser.add_argument("--target_uri", required=True)
parser.add_argument("--profile_name", required=True)
parser.add_argument("--file_type", required=True)
parser.add_argument("--file_url_or_path", required=True)
parser.add_argument("--header")
args = parser.parse_args()

# auth
AUTH_TOKEN = b64encode(f"{USER_ID}:{TOKEN}".encode('utf-8')).decode('utf-8')

# functions
def secondly(tokenSessionID):
	url = "https://domain"
	payload = "{}"
	headers = {
		'Content-Type': 'application/json',
        'Cookie': 'NSC_JOx=x'   
	}
	response = requests.request("POST", url, headers=headers, data = payload)
	
	if response.status_code==200:
		response_data= json.loads(response.json()['EntryPointJsonResult'])
		if 'accessToken' in response_data:
			print("accessToken:" , response_data['accessToken'])
			accessToken=response_data['accessToken']
		else:
			print("No accessToken in the response")
	else:
		print("response code:",response.status_code,response.text)
	
	
	return accessToken
	
	
def get_root_url(website_url):
    parsed_url = urlparse(website_url)
    root_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    return root_url

def encode_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()
        encoded_content = b64encode(file_content)
        encoded_string = encoded_content.decode('utf-8')
        return encoded_string
    except Exception as e:
        return str(e)

def get_id_from_name(scan_profile_name):
    headers = {
    'accept': 'application/json',
    'authorization': f'Basic {AUTH_TOKEN}'
    }

    response = requests.request("GET", f"{URL}/api/1.0/scanprofiles/get?name={scan_profile_name}", headers=headers, verify=False)
    return response.json()['ProfileId']

def get_id_from_url(website_url):
    headers = {
    'accept': 'application/json',
    'authorization': f'Basic {AUTH_TOKEN}'
    }

    response = requests.request("GET", f"{URL}/api/1.0/websites/get?query={website_url}", headers=headers, verify=False)
    return response.json()['Id']

def create_profile(target_uri, profile_name, file_type, file_url_or_path, header):
    payload_dict = {
        "AgentGroupId": None,
        "AgentId": None,
        "CreateType": "Website",
        "IsShared": True,
        "IsTimeWindowEnabled": False,
        "PolicyId": POLICY_ID,
        "ProfileName": profile_name,
        "ReportPolicyId": REPORT_POLICY_ID,
        "TargetUri": target_uri,
        "UserId": USER_ID,
        "AdditionalWebsites": [],
        "CrawlAndAttack": False,
        "FindAndFollowNewLinks": False,
        "Scope": "WholeDomain",
        "Tags": []
    }

    if file_url_or_path.startswith("http"):
        payload_dict["ImportedFiles"] = [
            {
                "Content": None,
                "FileName": "",
                "ImporterType": file_type,
                "URL": file_url_or_path,
                #"ApiURL": None,
                "Type": "LinkImportUrl"
            }
        ]
    else:
        payload_dict["ImportedFiles"] = [
            {
                "Content": encode_file(file_url_or_path),
                "FileName": os.path.basename(file_url_or_path),
                "ImporterType": file_type,
                "URL": None,
                #"ApiURL": None,
                "Type": "LinkImportFile"
            }
        ]

    if header:
        hname, hvalue = header.split(":")
        payload_dict["HeaderAuthentication"] = {
                "Headers": [
                {
                    "Name": hname,
                    "Value": hvalue,
                    "OriginalName": None,
                    "IsReplacedCredentials": False
                }
                ],
                "IsEnabled": True
        }

    payload = json.dumps(payload_dict)
    print(payload)
    headers = {
        'accept': 'application/json',
        'authorization': f'Basic {AUTH_TOKEN}',
        'content-type': 'application/json',
    }

    response = requests.request("POST", f"{URL}/api/1.0/scanprofiles/new", headers=headers, data=payload, verify=False)

    try:
        profile_id = response.json()['ProfileId']
        print(f"{profile_name} is created ({profile_id})") 
        return profile_id
    except:
        if "name already exists" in response.text:
            profile_id = get_id_from_name(profile_name)
            payload_dict["ProfileId"] = profile_id
            payload = json.dumps(payload_dict)

            response = requests.request("POST", f"{URL}/api/1.0/scanprofiles/update", headers=headers, data=payload, verify=False)
            print(f"{profile_name} is updated ({profile_id})")
            return profile_id
        else:
            print(f'Status Code: {response.status_code} | Error: {response.text}')
            return None
   
    
def initiate_scan(website_url, profile_id):
    root_url = get_root_url(website_url)
    website_id = get_id_from_url(root_url)

    payload_dict = {
        'WebsiteId': website_id, 
        'ProfileId': profile_id, 
        'ScanType': 'FullWithSelectedProfile', 
        'VcsCommitInfoModel': {
            'IntegrationSystem': 'AzureDevOps',
            'CiBuildConfigurationName' : ENV_VARS.get("SYSTEM_TEAMPROJECT", "unknown"), 
            'CiBuildHasChange': ENV_VARS.get("BUILD_SOURCEVERSION", "unknown"),
            'CiBuildId': ENV_VARS.get("BUILD_BUILDID", "unknown"),
            'CiBuildUrl': ENV_VARS.get("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "unknown"), 
            'Committer': ENV_VARS.get("BUILD_REQUESTEDFOREMAIL", "unknown"),
            'VcsName': ENV_VARS.get("BUILD_REPOSITORY_PROVIDER", "unknown"),
            'VcsVersion': ENV_VARS.get("BUILD_SOURCEVERSION", "unknown"),
        }
    }

    payload = json.dumps(payload_dict)

    headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Basic {AUTH_TOKEN}'
    }

    response = requests.request("POST", f"{URL}/api/1.0/scans/CreateFromPluginScanRequest", headers=headers, data=payload , verify=False)
    scan_id = response.json()["ScanTaskId"]
    print(f"scan is initiated ({scan_id})")


def create_scan(target_uri, profile_name, file_type, file_url_or_path, header):
    profile_id = create_profile(target_uri, profile_name, file_type, file_url_or_path, header)
    initiate_scan(target_uri, profile_id)
    
def firstly():
	url = "https://domain"
	payload = "{}"
	headers = {
  		'Content-Type': 'application/json',
  		'Cookie': 'NSC_JOx=x'  
	}

	response = requests.request("POST", url, headers=headers, data = payload)
	if response.status_code==200:
		response_data= json.loads(response.json()['EntryPointJsonResult'])
		if 'tokenSessionID' in response_data:
			print("tokenSessionID:" , response_data['tokenSessionID'])
			tokenSessionID=response_data['tokenSessionID']
		else:
			print("No tokenSessionID in the response")
	else:
		print("response code:",response.status_code,response.text)
	return tokenSessionID
	

#Main
test=firstly()
accesstoken="Authorization: Bearer "+secondly(test)
create_scan(target_uri=args.target_uri, profile_name=args.profile_name, file_type=args.file_type, file_url_or_path=args.file_url_or_path, header=accesstoken)

