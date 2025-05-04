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
