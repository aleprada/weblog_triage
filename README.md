**Weblogs Autotriage**

This project is based on the bash script showed on the course "[SDF:Weblog Forensics](https://www.udemy.com/course/sdf-weblog-forensics/)" by Michael Leclair, 
the author of the [Surviving Digital Forensics](https://digitalforensicsurvivalpodcast.com/surviving-digital-forensics/) podcast.

I am working in this Python version with the same functionality, thus 
to identify odd behaviours in logs based on 3 aspects: **Indicators of Compromise (IoCs)**, **Frequency** and **Attack patterns**.

**What type of data is searched?**
* **IoCs**: Using a list of IoC's (e.g. iocs.txt) or IoCs stored on MISP.
* **Frequency**: IP, HTTP request methods, Successful request status, User Agents, Byte size. 
* **Attack Patterns**:SQLi, XSS, Path Traversal, Webshells and Backdoors, Encoding, 
  Base64, Command Injection, Admin Site request and popular webserver misconfigurations.
  
I've also added an integration with MISP(Malware Information Sharing Platform) 
using PyMISP in order to pull events from MISP instances and checking 
if some event attributes such as IPs or URLs are found in the logs that 
are being analysed.

**Using Weblog Triage**

IoC's analysis
```bash 
python weblog_triage.py -f path_to_log -i path_to_ioc_list.txt
```
IoC's analysis using MISP instance
```bash 
python weblog_triage.py -f path_to_log -m 
```
Attack patterns analysis
```bash 
python weblog_triage.py -f path_to_log -a
```
Frequency analysis

```bash 
python weblog_triage.py -f path_to_log -c
```

Total analysis
```bash 
python weblog_triage.py -f path_to_log -t path_to_ioc_list.txt
```

The results will be stored inside the folder **"reports"**, creating a 
a new folder with the date and time each time the program is executed.

**Possible next steps**
* Performance enhancement
* Reduce false positives.
* Integration with S3 API
* Integration with CloudWatch?
