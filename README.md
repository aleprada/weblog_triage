**Weblogs Autotriage**

This project is based on the bash script showed on the course "[SDF:Weblog Forensics](https://www.udemy.com/course/sdf-weblog-forensics/)" by Michael Leclair, 
the author of the [Surviving Digital Forensics](https://digitalforensicsurvivalpodcast.com/surviving-digital-forensics/) podcast.

I am working in this Python version with the same functionality, thus to identify
odd behaviours in logs based on 3 aspects: IoCs, frequency and patterns.

Currently, only the log parsing and some basic structures are implemented. I will be adding the analytical part in
the coming days/weeks.

**3rd party integrations**

The original script only allowed to correlate an IoC list with the logs that are being analyzed.
My idea is to add some 3rd party integrations in order to allow the correlation with MISP
(Malware Information Sharing Platforms) as well as other sources such as
VirusTotal.
