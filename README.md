# SOC Automation (In Progress)

**Acknowledgment:** This project benefited greatly from the insights and tutorials provided by the YouTube channel [MyDFIR](https://www.youtube.com/@mydfir). Their comprehensive videos were invaluable in understanding and implementing the various components of the SOC Automation Lab.

## Objective

The SOC Automation lab is to explore how automation enhances incident response, accelerates threat detection, and streamlines SOC workflows. Fully integrated SOAR solution incorporating Wazuh & TheHive for case management.

### Skills Learned

- **Automate Event Collection and Analysis:** Ensure security events are collected and analyzed in real-time with minimal manual intervention, enabling proactive threat detection and response.
- **Streamline Alerting Process:** Automate the process of generating and forwarding alerts to relevant systems and personnel, reducing response times and minimizing the risk of overlooking critical incidents.
- **Enhance Incident Response Capabilities:** Automate responsive actions to security incidents, improving reaction time, consistency, and effectiveness in mitigating threats.
- **Improve SOC Efficiency:** Reduce the workload on SOC analysts by automating routine tasks, allowing them to focus on high-priority issues and strategic initiatives.

### Tools Used

- **Wazuh:** An open-source, enterprise-grade security monitoring platform that serves as the central point for event collection, analysis, and alerting.
- **Shuffle:** A flexible, open-source security automation platform that handles workflow automation for alert processing and response actions.
- **TheHive:** A scalable, open-source Security Incident Response Platform designed for SOCs to efficiently manage and resolve incidents.
- **VirusTotal:** An online service that analyzes files and URLs to detect various types of malicious content using multiple antivirus engines and scanners.
- **Cloud Services or Additional VMs:** Wazuh and TheHive can be deployed either on cloud infrastructure or additional virtual machines, depending on your resource availability and preferences.

## Steps
![SOCAutomation](https://github.com/user-attachments/assets/a2d11381-ebbf-4237-a9d0-6fc8338340b1)

### 1. Set up a Windows 10 Pro VM. You can use any software of your choosing. I will be using VirtualBox. I will be setting it with 4gb of memory and 50gb of storage. 
![windowsVM](https://github.com/user-attachments/assets/51c3868c-d599-4263-87dc-6b9cb93705d5)


### 2. Install Sysmon on the VM using configuration file from [Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)
After extracting the Sysmon folder be sure to place the config file in the Sysmon folder before running the install.
![sysmon](https://github.com/user-attachments/assets/27533ae1-6a0d-48f8-8849-983c042468d9)

### 3. Now we set up our Servers for Wazuh and TheHive. I am using [DigitalOcean](https://www.digitalocean.com) but any provider will do. 
![wazuh](https://github.com/user-attachments/assets/0a8a47f8-4f7c-428b-bfbe-81ff837afea1)
![hive](https://github.com/user-attachments/assets/30b26036-9b3d-4917-8964-c0ae4a1a1399)

Be Sure to add firewall rules for both servers to only allow traffic from your IP address 
![Firewall](https://github.com/user-attachments/assets/27250dae-f2f3-4fcb-83f3-4d8fe86c9afb)

### 4. SSH into the Wazuh server and install Wazuh
Be sure to run update and upgrade before installing Wazuh
```
sudo apt-get update && sudo apt-get upgrade -y
```
Here is the curl command for Wazuh. Note there may be a more recent version when you are reading this.
```
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
Note at he end of the Wazuh install there will be an admin username and password. Be sure to save this so you can access the Wazuh dashboard at https://"wazuh-server-public-ip"
![wazuhinstall](https://github.com/user-attachments/assets/70642d5a-17e8-440f-9e13-cbd376b94632)

### 5. SSH into the TheHive server and install TheHive
This is going to take a bit more time because we need a few dependecies, Java, Cassandra, and ElasticSearch before installing TheHive.
We start by installing the necessary dependencies for TheHive:
```
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```
Install Java:
```
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```
Install Cassandra:
Cassandra is the database used by TheHive for storing data.
```
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```
Install Elasticsearch:
Elasticsearch is used by TheHive for indexing and searching data.
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```
Optional Elasticsearch Configuration:
Create a `jvm.options` file under `/etc/elasticsearch/jvm.options.d` and add the following configurations to optimize Elasticsearch performance:
```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```
Install TheHive:
```
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```
![hiveinstall](https://github.com/user-attachments/assets/ecd143be-696e-431e-b270-6dad2f81eec1)

### 6. Configure The Cassandra Database
We will need to modify the `cassandra.yaml` file:
```
nano /etc/cassandra/cassandra.yaml
```
Note: use ctrl+W to find the fields
First change the cluster name, it can be anything just remember it
![clustername](https://github.com/user-attachments/assets/5518ecab-18ed-4cb7-927a-136a4b04fa8e)

Set the `listen_address` to your Hive server's public IP, dont leave it as localhost
![listenaddress](https://github.com/user-attachments/assets/aeb7be8d-0c35-4e6e-9bfa-82f2cdfe757c)

Set the `rpc_address` to your Hive server's public IP, dont leave it as localhost
![rpcaddress](https://github.com/user-attachments/assets/fb77fd87-866a-48ad-b804-4036b237a084)

Lastly change the seed address in the `seed_provider` section to your Hive server's public IP, dont leave it as the default
![seeds](https://github.com/user-attachments/assets/212da0f8-140d-4791-86e4-e2e9faa4b03d)

Note: use ctrl+X to close and type Y to save

Stop the Cassandra service:
```
systemctl stop cassandra.service
```
Remove the old Cassandra data files since we installed TheHive using the package:
```
rm -rf /var/lib/cassandra/*
```
Start the Cassandra service again:
```
systemctl start cassandra.service
```
Check the Cassandra service status to ensure it's running:
```
systemctl status cassandra.service
```
![cassandraservice](https://github.com/user-attachments/assets/4ba31293-74d2-4b76-ba7f-075ff98bd6f3)

### 7. Configure ElasticSearch
ElasticSearch is used for data indexing in TheHive. Configure it by modifying the `elasticsearch.yml` file:
```
nano /etc/elasticsearch/elasticsearch.yml
```
Optionally, change the cluster name.
Uncomment the `node.name` field.\
Uncomment the `network.host` field and set the IP to TheHive's public IP.\
Optionally, uncomment the `http.port` field (default port is 9200).\
Optionally, uncomment the `cluster.initial_master_nodes` field, remove `node-2` if not applicable. In this case I only use node-1.
![elasticsearch](https://github.com/user-attachments/assets/f3298f13-6f02-44b7-9865-133aa5f83d2d)

Start and enable the Elasticsearch service and check its status:
```
systemctl start elasticsearch
```
```
systemctl enable elasticsearch
```
```
systemctl status elasticsearch
```
![startenablestatuselastic](https://github.com/user-attachments/assets/dc691ffb-0b1e-45b0-9271-ec0ccf866b8d

### 8. Configure TheHive
Ensure the `thehive` user and group have access to the necessary file paths. If `root` has access to the `thehive` directory, change the ownership.
```
ls -la /opt/thp
```
```
chown -R thehive:thehive /opt/thp
```
![thehivefileaccess](https://github.com/user-attachments/assets/30b11fa8-2685-4f5a-96f5-62d2968d6d0d)

Now, configure TheHive's configuration file:
```
nano /etc/thehive/application.conf
```

Modify the `database` and `index config` sections.\
Change the `hostname` IP to TheHive's public IP.\
Set the `cluster.name` to the same value as the Cassandra cluster name ("autosoclab" in this example).\
Change the `index.search.hostname` to TheHive's public IP.\
At the bottom, change the localhost in `application.baseUrl` to TheHive's public IP.
![thehiveconfig](https://github.com/user-attachments/assets/b24b5edc-942c-4d94-96d2-12f69f3555d0)

Important note: If you cannot access TheHive, ensure all three services (Cassandra, Elasticsearch, and TheHive) are running. If any of them are not running, TheHive won't start.

If all services are running, access TheHive from a web browser using TheHive's public IP and port 9000:
```
http://"hive public ip":9000
```
Default credentials for accessing TheHive on port 9000:
```
Username: admin@thehive.local
Password: secret
```
![hivelogin](https://github.com/user-attachments/assets/3417607f-2f70-420a-841a-99b02b5cb6f6)

### 9. Configure Wazuh
login usign the admin creds from the initial install to the Wazuh web manager on your windows VM by going to `https://"wazuh public ip"`
![wazuhconfig](https://github.com/user-attachments/assets/011cace4-a24c-4091-ba6b-f65dec2f2a20)
Click on add agent and Select Windows as the OS\
Set the server address to the Wazuh server public IP.\
The agent name can be whatever you want.\
Copy and run the install command into an admin poweshell terminal on the VM\
Start the Wazuh service in the terminal using:
```
NET START WazuhSvc
```

### 10. Set Up A Custom Alert
First we need to set the Wazuh client to take in Sysmon logs. On the Windows client machine, navigate to `C:\Program Files (x86)\ossec-agent`. Create a back up copy of the `ossec.conf` file. Now open the `ossec.conf` file with an adminstrator notepad.\
Add the config highlighted below to the ossec file and save the file. 
![wazuhsysmonconfig](https://github.com/user-attachments/assets/f0b20664-4d17-46c9-81dd-7005b513d79f)

Note you can find the name of the Sysmon service in Event Viewer:
![Sysmonname](https://github.com/user-attachments/assets/3cc0c5b2-3aa3-474d-9fd1-32ea5c5525eb)

Anytime we change a config we need to restart the service.
![restartwazuh](https://github.com/user-attachments/assets/f521b023-8716-475c-991d-c571157181ee)

By default, Wazuh only logs events that trigger a rule or alert. We need to log all events.
Connect to the Wazuh server via SSH 
Always back up config files before you modify them:
```
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf
```
open the file:
```
nano /var/ossec/etc/ossec.conf
```
Change the `<logall>` and `<logall_json>` options under the `<ossec_config>` section from "no" to "yes".
![wazuhossec](https://github.com/user-attachments/assets/5785791d-2bb2-4314-9803-d6e2e66c1871)

Remember to restart the Wazuh manager service:
```
systemctl restart wazuh-manager.service
```

To enable Wazuh to ingest the archived logs, modify the Filebeat configuration:
```
nano /etc/filebeat/filebeat.yml
```
Change the archives enabled to `true` 
![filebeatconfig](https://github.com/user-attachments/assets/79ad027b-e2b1-4af2-97dc-d7fdec050c9b)

Remember to restart filebeat:
```
systemctl restart filebeat
```

Now lets run malware on the Windows VM. Download mimikatz_trunk.zip here: `https://github.com/gentilkiwi/mimikatz/releases`\
Mimikatz is commanly used by attackers to extract crednetials from memory. You will probably need to exclude the downloads folder from Windows Security and disable your browsers protections. Otherwise the Windows VM will just block you from downloading the file\
Once downloaded and unzipped open and admin powershell and cd to the mimikatz folder and run it.
![mimikatz](https://github.com/user-attachments/assets/93b7ae22-b2d2-4a65-981d-db5418e21d02)

Now we need to create a new index in the Wazuh web manager to search the archived logs.
From the left-side menu, go to "Stack Management" > "Index Patterns" > "Create index pattern".\
Name it `wazuh-archives-**`
![wazuhindexpattern](https://github.com/user-attachments/assets/bb953259-a7d9-4b73-9b48-b322b7273d3c)
On the next page select "timestamp" as the time field and create the index

From the left menu go to "Discover" and select the new index.
![wazuhmimikatz](https://github.com/user-attachments/assets/375b9ea2-732d-4487-a4f1-e200e4389bef)

You should see mimikatz logs if not try rerunning mimikats:
![rerunmimikatz](https://github.com/user-attachments/assets/b10327fc-185d-49a3-89fb-62b874a54850)

Take note of the original file name field in the log details. This is what we will use to create a custom rule.
![originalfilename](https://github.com/user-attachments/assets/60173450-1822-4a9c-88f6-3462635f3b1d)

To create the rule: "Home" > "Wazuh dropdown" > "Management" > "Rules" > "Manage Rule Files" > Search for Sysmon
![ruleswazuh](https://github.com/user-attachments/assets/06f8e873-a65c-4ee3-af14-052de146fea7)

Search for Sysmon rules, "0800-sysmon_id_1.xml" are the rules for event ID 1. Using the eye to learn how to structure a custom rule by referencing the sysmon rules. Then click Custome Rule and click the pencil on the local rules to write a rule:\
![customwazuhrule](https://github.com/user-attachments/assets/377ec4e3-3c60-4e97-93e0-5ba6d953a5c4)
After saving you will be prompted to restart the Wazauh manager, do so. 

Now lets test our rule. In the windows VM rename the mimikatz exe. This is why we set the originalFileName as the property in the rule. No matter what the name has been changed to, our custom rule should detect it.\
![verysafe](https://github.com/user-attachments/assets/ba3f3a97-f883-4b85-a1a0-5cf3cd5236f4)

Now in Securty Events on the Wazuh web manager you should see the rule getting caught:
![mimikatzdetected](https://github.com/user-attachments/assets/d07e2b2d-9207-4932-90f7-ff8e4ac872ca)


