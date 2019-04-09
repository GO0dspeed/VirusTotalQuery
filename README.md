# VirusTotalQuery
Python script to query the VirusTotal API for information on hashes

# Usage: 
```

./queryVT.py -f f24b07854acbd3525e8c3fa41f780f659c72c8422f01fea9994bda78a9f112ac

Results: 

Scan date: 2019-04-05 06:18:40
32 out of 67 engines detected this file/url
The sha256 hash of this file is f24b07854acbd3525e8c3fa41f780f659c72c8422f01fea9994bda78a9f112ac 

AntiVirus Detections:

CAT-QuickHeal         PUA.Mindsparki.Gen  
Malwarebytes          PUP.Optional.MindSpark
SUPERAntiSpyware      PUP.MindSpark/Variant
Alibaba               Toolbar:Win32/Agent.b162eaea
K7GW                  Adware ( 004e15d51 )
K7AntiVirus           Adware ( 004e15d51 )
Cyren                 W32/Adware.JQZB-7335
ESET-NOD32            Win32/Toolbar.MyWebSearch.BA potentially unwanted
TrendMicro-HouseCall  TROJ_GEN.R020H0CCP19
Kaspersky             not-a-virus:HEUR:WebToolbar.Win32.Agent.gen
Avast                 Win32:UnwantedSig [PUP]
Endgame               malicious (high confidence)
Emsisoft              Application.WebToolbar (A)
Comodo                ApplicUnwnt@#1t3azi5m8luxp
DrWeb                 Adware.MyWebSearch.145
VIPRE                 MyWebSearch.J (v) (not malicious)
Invincea              heuristic           
SentinelOne           DFI - Malicious PE  
Antiy-AVL             GrayWare/Win32.StartPage.gen
Microsoft             PUA:Win32/MyWebSearch
ViRobot               Adware.MyWebSearch.380056.C
ZoneAlarm             not-a-virus:HEUR:Downloader.Win32.Agent.gen
GData                 Win32.Adware.Mindspark.E
AhnLab-V3             PUP/Win32.Mindspark.R233545
VBA32                 Adware.Agent        
Zoner                 Trojan.Win32.70060  
Rising                PUF.MySearch!1.AEA3 (CLASSIC:bWQ1OnZ3N/AEVQMtiToiO3hiHy0)
Yandex                PUA.Agent!          
Fortinet              Adware/Agent        
AVG                   Win32:UnwantedSig [PUP]
CrowdStrike           win/malicious_confidence_100% (D)
Qihoo-360             Win32/Virus.WebToolbar.5bb

```

## Description

This program is designed to utilize the VirusTotal free API to check the hashes of files to verify detection

This program will output the following:

Date of scan

How many engines have detected the file

The files hash

A table of which engines detected the file and the results
