#!/usr/bin/env python3

# Python script that integrates Wazuh with TheHive for automatic creation of incidents
# Author: Anthony M

import sys
import json
import requests

# Read the alert file path, and load with json
alert_file = open(sys.argv[1])
alert_json = json.loads(alert_file.read())
alert_file.close()

# Constants
HOOK_URL = r"http://192.168.133.131:9000/api/v1/alert" #TheHive's API endpoint
API_KEY = r"<YOUR API KEY>" # API key of user "service1"

# Extract some alert fields
rule_severity = alert_json['rule']['level']
rule_id = alert_json['rule']['id']
rule_description = alert_json['rule']['description']
rule_mitre_id = alert_json['rule']['mitre']['id']
agentname = alert_json['agent']['name']
agent_ip = alert_json['agent']['ip']
timestamp = alert_json['timestamp']

# --Temporary (to view alert JSON structure)--
"""
with open("/tmp/wazuh_alert.json", "w") as f:
    json.dump(alert, f, indent=2)
"""

# Request Fields
headers = {
	   'Authorization': f"Bearer {API_KEY}",
	   'content-type': 'application/json'
}

json_data = {
	"title": rule_description,
	"type": "wazuh",
	"source": "wazuh",
	"sourceRef": f"wazuh-{rule_id}-{timestamp}",
	"severity": min(rule_severity, 4),
	"description":(
		f"Rule ID: {rule_id}\n"
		f"MITRE: {rule_mitre_id}\n"
		f"Agent Name: {agentname}\n"
		f"Agent IP: {agent_ip}"
	)
}

# Make POST request
try:
	response = requests.post(HOOK_URL, data=json.dumps(json_data), headers=headers)

except Exception:
	sys.exit(-1)

sys.exit(0)