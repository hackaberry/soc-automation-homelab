# SOC Automation Homelab

## Overview
In this project, I document the design, deployment, configuration, and validation of a small-scale SOC home lab. The environment integrates Wazuh (SIEM) with TheHive (Incident Response Platform) to demonstrate the detection, alerting, and automated incident creation of the alerts.

My goal throughout this project is to:
- Demonstrate **blue team skills**, including setting up a SOC home lab, monitoring endpoint devices, creating custom rules, and automating the creation of incidents through Security Orchestration, Automation, and Response (SOAR), to increase productivity and allocate valuable time to incident response.

### Project Outline
- [Environment Setup](#part-1---environment-setup)
- [Platform Configuration](#part-2---platform-configuration)
- [Creating Our First Rule](#part-3---creating-our-first-rule)
- [TheHive Integration](#part-4---thehive-integration)
- [Wazuh Automation (SOAR)](#part-5---wazuh-automation-soar)



---

## Architecture

### Components
Throughout this project, I will be using VMware to launch the following devices:
- **Windows 11** - Acts as the endpoint I will be monitoring.
- **Wazuh Server (Ubuntu)** – Will run the Wazuh server (SIEM).
- **TheHive Server (Ubuntu)** – Will run the Incident response and case management platform.

---

## Part 1 - Environment Setup
The focus of this section is to setup the correct environment for the home-lab. 
### Windows 11 Endpoint
I downloaded the [Windows 11 ISO](https://www.microsoft.com/en-us/software-download/windows11) and launched the VM. This device represents the client.

**Virtual Machine Specifications:**
- OS: Windows 11 25H2
- RAM: 4 GB
- Storage: 64 GB
- Network: NAT

### Sysmon Deployment
Running Sysmon is optional but highly recommended, as it gives us far more detailed logs.

I installed version 15.15, and used the configuration file from the [Sysmon Modular project](https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml), which significantly reduces noise in the security events.

![Sysmon Event Configuration](Images/Screenshot%20(1).png)

---

### Wazuh Server Installation
I will be running the Wazuh SIEM server in its own dedicated VM

**Virtual Machine Specifications:**
- OS: Ubuntu 24.04.3
- RAM: 4 GB
- Storage: 40 GB
- Network: NAT

To install Wazuh, we simply follow the steps in the [documentation](https://documentation.wazuh.com/current/quickstart.html)
![Image](Images/Screenshot%20(3).png)
Once the installation is complete, we need to note down the credentials displayed to us, which are used to login to the web interface.
![Image](Images/Screenshot%20(4).png)

---

### TheHive Server Installation
I will be running TheHive server on another dedicated VM.

**Virtual Machine Specifications:**
- OS: Ubuntu 24.04.3
- RAM: 8 GB
- Storage: 60 GB
- Network: NAT

Before we can install TheHive, we first need to install two dependencies. I followed the entire installation process on the TheHive's [documentation page](https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/#step-2-set-up-the-java-virtual-machine-jvm).
#### Dependencies
##### Cassandra 
Cassandra acts as the database used by TheHive. Once installed, we can verify it's running as expected with `systemctl status cassandra`
![Image](Images/Screenshot%20(7).png)
The configuration file `/etc/cassandra/cassandra.yaml` may require some changes depending on the environment setup. 
##### Elasticsearch 
ElasticSearch is used for indexing and searching. Again, we can verify its status with `systemctl status elasticsearch`
![Image](Images/Screenshot%20(9).png)
The configuration file `/etc/elasticsearch/elasticsearch.yml` may also require some changes depending on the environment setup. 
#### TheHive Compatibility Note
Installing TheHive was a little trickier, as I ran into compatibilty issues between Elasticsearch version 8 and TheHive version 4, which was silently causing startup failures. Once I figured this out, I purged TheHive's installation completely and installed an older version (7). Finally, everything seemed to be working correctly, and the web interface was up and running on port 9000.
![Image](Images/Screenshot%20(10).png)
According to the documentation, default credentials are `admin@thehive.local`:`secret`. Obviously, we'll want to change these as soon as possible.

---
## Part 2 - Platform Configuration

### Wazuh Agent Deployment
Now let's configure the Wazuh agent on the endpoint we will be monitoring, which in this case is the Windows 11 VM. The easiest way of doing this, is by logging in to the Wazuh dashboard from the Windows 11 VM and deploying the new agent from there. I will call this agent `DESKTOP-00`

Deploying the agent is very easy. We simply click on deploy a new agent, and copy paste the command given to us by Wazuh on PowerShell with administrator privileges. If everything goes well, we should see the following message showing the Wazuh service was started successfully.
![Image](Images/Screenshot%20(12).png)
We can also confirm the agent is active on the dashboard

![Image](Images/Screenshot%20(13).png)

### Log Collection Configuration
I extended the Wazuh agent to also include **Sysmon logs** and **Windows Defender / Antivrus events**. This is achieved by editing the agent's configuration file `ossec.conf` and adding the fields.
![Image](Images/Screenshot%20(16).png)

---

## Part 3 - Creating our first rule

### Initial Alert Validation
Before we even begin creating rules, let's first do a baseline test to ensure the Wazuh agent is able to talk to the server. 

To achieve this, I'm simply going to disable Windows Defender real-time protection
![Image](Images/Screenshot%20(17).png)

If everything is setup correctly, we should see an alert generated from this action on Wazuh, which corresponds to event id 5001
![Image](Images/Screenshot%20(18).png)
Great. This confirms the Wazuh server is now ingesting event data from the Windows 11 endpoint.

---

### PowerShell Detection Rule
Let's create our first custom rule. This rule will look for PowerShell commands containing the `Invoke-Expression` or its alias (`IEX`) cmdlet. While these could be used by sysadmins for legitimate purposes, its presence is usually very alarming otherwise.


#### Enabling Script Block Logging
In order to monitor PowerShell activity, we need to enable something called **PowerShell Script Block Logging**. This can be achieved in various ways, but the easiest is just modifying the Windows Registry by adding a new DWORD (32-bit) key named `EnableScriptBlockLogging`, and setting its value to 1. The path we add this item in is shown in the screenshot below.
![Image](Images/Screenshot%20(19).png)
Once this tweak is set, we can now monitor for PowerShell activity in Event Viewer, under the path: `Applications and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational`. 

The following screenshot shows the `whoami` command I executed for demonstration purposes
![Image](Images/Screenshot%20(20).png)

Finally, in order to monitor these events on Wazuh, we again edit the `ossec.conf` file to include PowerShell events.
![Image](Images/Screenshot%20(21).png)

#### Custom Wazuh Rule
Now it's time to create our custom rule. To do this we head over to the Wazuh `local_rules.xml` file. 
![Image](Images/Screenshot%20(22).png)

I will be referencing [Wazuh's documentation on syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) to create this rule

The rule looks as follows
```xml
<rule id="100010" level="12">
  <field name="win.system.eventID">4104</field>
  <match>Invoke-Expression|iex</match>
  <description>PowerShell Invoke-Expression (IEX) execution detected</description>
  <mitre>T1059.001</mitre>
</rule>
```
1. The rule ID is just an arbitrary number that is above 100000 to avoid conflicting rule IDs.
2. The field name filters for events with a specified event id.
3. Match is used to match keyword(s) contained in the event.
4. Description contains any comments we want the alert to have.
5. The Mitre section is optional, but I added it to to map it to  [MITRE ATT&CK](https://attack.mitre.org/).

One we finish, we can save the xml file, and restart the Wazuh server for good measure.
#### Rule Validation
Let's test this newly created rule and ensure it generates an alert on Wazuh. To do this, I'll use WinPEAS, which is a popular post-exploitation enumeration script for Windows.
![Image](Images/Screenshot%20(24).png)
When we head over to Wazuh and filter for event ID 4104 (which represents PowerShell activity), we will find the alert in fact did trigger for the command we executed
![Image](Images/Screenshot%20(25).png)
This shows the rule was successfully created on Wazuh.

---

## Part 4 – TheHive Integration

To increase workflow productivity, I want to automate the creation of incidents on TheHive. The way we achieve this is by integrating a custom script into Wazuh. This script will call TheHives API endpoint (through its REST API), and in turn create a new incident containing data relevant to the alert.

### Organization and User Setup
To begin, we create an organization in TheHive (I named it `test1`). Additionally, I created the following users:
1. `John` - This user represents a SOC analyst who manages incidents and triages alerts.
2. `service` - This user is merely a bot with enough permissions to create alerts via the API.

![Image](Images/Screenshot%20(32).png)

### API Key Generation

I will generate a new API key for the user `service1` so we can start interacting with TheHive programmatically. We'll need to pass this key as authorization to any POST request we make.

---

### Manual API Testing

Let's first obtain a proof-of-concept by manually calling the API with test data, and confirm the creation of an incident. 

To understand what fields are required by TheHive and how to use the API, we can reference the [documentation](https://docs.strangebee.com/thehive/api-docs/#tag/Alert/operation/Create%20Alert.). Upon reading these docs, we learn what fields are required in the JSON.
![Image](Images/Screenshot%20(40).png)

This in turn is what I include in the POST request as shown in the screenshot below
![Image](Images/Screenshot%20(41).png)

We can now call the API with the provided data manually by simply executing the cURL command:

![Image](Images/Screenshot%20(37).png)

Upon logging in as SOC analyst user `John`, we can confirm the alert was created successfully.
![Image](Images/Screenshot%20(38).png)

This proof-of-concept shows us we can now simply integrate a script of this nature with some modifications to Wazuh, and incidents will automaticly be created, containing important information about the alert generated. This saves the team valuable time that can be used for incident response.

---

## Part 5 – Wazuh Automation (SOAR)

### Integration Design
I will be using this [blogpost](https://wazuh.com/blog/how-to-integrate-external-software-using-integrator/) on the Wazuh website to help guide me in integrating custom scripts. 

From reading this blog, we learn that to add a custom script:
1. The name of the script must start with `custom-`.
2. We must include a shebang first thing in the script (no surprise there).
3. First argument read by the script is the `alert file`, second is the `api_key` (optional), and third is the `hook_url` (again optional). The reason the `api_key` and `hook_url` are optional is that they can simply be put in the script itself, making it redundant to include it in the `ossec.conf` file.
4. We must give execute permissions on the script to user `wazuh`.
5. The script must be located in `/var/ossec/integrations`.

With all of this in mind, I will create a script called `custom-thehive.py`, and only trigger it for rule `91837` which is a default rule id on Wazuh indicating `Invoke-Expression` (or `IEX`) was executed on the remote host. 

My integration in the `/var/ossec/etc/ossec.conf` file then looks like so
![Image](Images/Screenshot%20(45).png)
<u>Note</u>: I decided not to include the `hook_url` or `api_key` fields as they are optional and will be part of my script anyway.

### Python Integration Script
As mentioned in the blog post, Wazuh only ever executes scripts located in the `/var/ossec/integrations` directory. Therefore, whatever script we wish to run, must be located there.

The below screenshot is the Python script I made. I will make sure to include it on Github.

The script simply reads the JSON data of the alert, extracts some fields I deemed were important, and makes a POST request to TheHives API endpoint, which in turns creates the incident.
![Image](Images/Screenshot%20(49).png)

Finally, I will create a symbolic link to this script named `custom-thehive` so Wazuh can find it.
![Image](Images/Screenshot%20(50).png)

---

### Integration Testing

Let's test this Wazuh integration and confirm an incident is created on TheHive upon generating our target alert from the Windows 11 machine. Similar to last time, I will mimic malicious activity by running `WinPEAS.ps1` and piping the raw strings to `IEX` for fileless execution

![Image](Images/Screenshot%20(52).png)

Making sure we are logged in as user `John` (the SOC analyst), we will in fact notice an incident from this action was created

![Image](Images/Screenshot%20(53).png)

Beautiful, this confirms our integration was successfully setup. Additionally, we can click on this incident and view more information about the alert that triggered.
![Image1](Images/Screenshot%20(54).png)

## Conclusion

By building and integrating Wazuh and TheHive from the ground up, I gained hands-on experience in security operations, and API-based integrations. The integration I showcased lays the groundwork for future response actions such as endpoint isolation, containment, and enrichment, mirroring how production SOC environments evolve over time.

---

