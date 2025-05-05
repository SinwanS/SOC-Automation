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
Default credentials for accessing TheHive on port 9000:
```
Username: admin@thehive.local
Password: secret
```
![hiveinstall](https://github.com/user-attachments/assets/ecd143be-696e-431e-b270-6dad2f81eec1)
