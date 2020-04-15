# Awesome Threat Detection and Hunting
[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

> A curated list of awesome threat detection and hunting resources


## Contents

- [Threat Detection and Hunting](#threat-detection-and-hunting)
    - [Tools](#tools)
        - [Alerting Engine](#alerting-engine)
        - [Endpoint Monitoring](#endpoint-monitoring)
        - [Network Monitoring](#network-monitoring)
             - [Fingerprinting Tools](#fingerprinting-tools)
    - [DataSet](#dataset)
    - [Resources](#resources)
        - [Frameworks](#frameworks)
        - [DNS](#dns)
        - [Command and Control](#command-and-control)
        - [Osquery](#osquery)
        - [Windows](#windows)
            - [Sysmon](#sysmon)
            - [PowerShell](#powershell)
        - [Fingerprinting](#fingerprinting)
        - [Research Papers](#research-papers)
        - [Blogs](#blogs)
    - [Videos](#videos)
    - [Trainings](#trainings)
    - [Twitter](#twitter)
- [Threat Simulation](#threat-simulation)
    - [Tools](#tools-1)
    - [Resources](#resources-1)
- [Contribute](#contribute)
- [License](#license)


## Threat Detection and Hunting


### Tools

- [MITRE ATT&CK Navigator](https://mitre.github.io/attack-navigator/enterprise/)([source code](https://github.com/mitre/attack-navigator)) - The ATT&CK Navigator is designed to provide basic navigation and annotation of ATT&CK matrices, something that people are already doing today in tools like Excel.
- [HELK](https://github.com/Cyb3rWard0g/HELK) - A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.
- [osquery-configuration](https://github.com/palantir/osquery-configuration) - A repository for using osquery for incident detection and response.
- [DetectionLab](https://github.com/clong/DetectionLab/) - Vagrant & Packer scripts to build a lab environment complete with security tooling and logging best practices.
- [Sysmon-DFIR](https://github.com/MHaggis/sysmon-dfir) - Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
- [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) - Sysmon configuration file template with default high-quality event tracing.
- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) - A repository of sysmon configuration modules. It also includes a [mapping](https://github.com/olafhartong/sysmon-modular/blob/master/attack_matrix/README.md) of Sysmon configurations to MITRE ATT&CK techniques.
- [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) - PowerShell Obfuscation Detection Framework.
- [Invoke-ATTACKAPI](https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI) - A PowerShell script to interact with the MITRE ATT&CK Framework via its own API.
- [Unfetter](https://github.com/unfetter-analytic/unfetter) - A reference implementation provides a framework for collecting events (process creation, network connections, Window Event Logs, etc.) from a client machine and performing CAR analytics to detect potential adversary activity.
- [Flare](https://github.com/austin-taylor/flare) - An analytical framework for network traffic and behavioral analytics.
- [RedHunt-OS](https://github.com/redhuntlabs/RedHunt-OS) - A Virtual Machine for Adversary Emulation and Threat Hunting. RedHunt aims to be a one stop shop for all your threat emulation and threat hunting needs by integrating attacker's arsenal as well as defender's toolkit to actively identify the threats in your environment.
- [Oriana](https://github.com/mvelazc0/Oriana) - Lateral movement and threat hunting tool for Windows environments built on Django comes Docker ready.
- [Bro-Osquery](https://github.com/bro/bro-osquery) - Bro integration with osquery
- [Brosquery](https://github.com/jandre/brosquery) - A module for osquery to load Bro logs into tables
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - A PowerShell Module for Hunt Teaming via Windows Event Logs
- [Uncoder](https://uncoder.io) - An online translator for SIEM saved searches, filters, queries, API requests, correlation and Sigma rules
- [Sigma](https://github.com/Neo23x0/sigma) - Generic Signature Format for SIEM Systems
- [CimSweep](https://github.com/PowerShellMafia/CimSweep) - A suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows
- [Dispatch](https://github.com/Netflix/dispatch) - An open-source crisis management orchestration framework
- [EQL](https://github.com/endgameinc/eql) - Event Query Language
  - [EQLLib](https://github.com/endgameinc/eqllib) - The Event Query Language Analytics Library (eqllib) is a library of event based analytics, written in EQL to detect adversary behaviors identified in MITRE ATT&CK™.
- [BZAR](https://github.com/mitre-attack/bzar) (Bro/Zeek ATT&CK-based Analytics and Reporting) - A set of Zeek scripts to detect ATT&CK techniques
- [Security Onion](https://github.com/Security-Onion-Solutions/security-onion) - An open-source Linux distribution for threat hunting, security monitoring, and log management. It includes ELK, Snort, Suricata, Zeek, Wazuh, Sguil, and many other security tools
- [Varna](https://github.com/endgameinc/varna) - A quick & cheap AWS CloudTrail Monitoring with Event Query Language (EQL)
- [BinaryAlert](https://github.com/airbnb/binaryalert) - Serverless, real-time & retroactive malware detection
- [hollows_hunter](https://github.com/hasherezade/hollows_hunter) - Scans all running processes, recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches).
- [ThreatHunting](https://github.com/olafhartong/ThreatHunting) - A Splunk app mapped to MITRE ATT&CK to guide your threat hunts
- [Sentinel Attack](https://github.com/BlueTeamLabs/sentinel-attack) - A repository of Azure Sentinel alerts and hunting queries leveraging sysmon and the MITRE ATT&CK framework
- [Brim](https://github.com/brimsec/brim) - A desktop application to efficiently search large packet captures and Zeek logs
- [YARA](https://github.com/virustotal/yara) - The pattern matching swiss knife

#### Alerting Engine

- [ElastAlert](https://github.com/Yelp/elastalert) - A framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch
- [StreamAlert](https://github.com/airbnb/streamalert) - A serverless, realtime data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using datasources and alerting logic you define

#### Endpoint Monitoring

- [osquery](https://osquery.io) ([github](https://github.com/osquery/osquery)) - SQL powered operating system instrumentation, monitoring, and analytics
- [Kolide Fleet](https://github.com/kolide/fleet) - A flexible control server for osquery fleets
- [Zeek Agent](https://github.com/zeek/zeek-agent) - An endpoint monitoring agent that provides host activity to Zeek
- [Velociraptor](https://github.com/Velocidex/velociraptor) - Endpoint visibility and collection tool
- [Sysdig](https://github.com/draios/sysdig) - A tool for deep Linux system visibility, with native support for containers. Think about sysdig as strace + tcpdump + htop + iftop + lsof + ...awesome sauce
- [go-audit](https://github.com/slackhq/go-audit) - An alternative to the Linux auditd daemon
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - A Windows system service and device driver that monitors and logs system activity to the Windows event log
- [OSSEC](github.com/ossec/ossec-hids) - An open-source Host-based Intrusion Detection System (HIDS)
- [WAZUH](https://github.com/wazuh/wazuh) - An open-source security platform
 
#### Network Monitoring

- [Zeek](https://github.com/zeek/zeek) (formerly Bro) - A network security monitoring tool
- [ntopng](https://github.com/ntop/ntopng) - A web-based network traffic monitoring tool
- [Suricata](https://suricata-ids.org) - A network threat detection engine
- [Snort](https://snort.org) ([github](https://github.com/snort3/snort3)) - A network intrusion detection tool 
- [Joy](https://github.com/cisco/joy) - A package for capturing and analyzing network flow data and intraflow data, for network research, forensics, and security monitoring
- [Netcap](https://github.com/dreadl0ck/netcap) - A framework for secure and scalable network traffic analysis
- [Moloch](https://github.com/aol/moloch) - A large scale and open source full packet capture and search tool
- [Stenographer](https://github.com/google/stenographer) - A full-packet-capture tool

##### Fingerprinting Tools

- [JA3](https://github.com/salesforce/ja3) - A method for profiling SSL/TLS Clients and Servers
- [HASSH](https://github.com/salesforce/hassh) - Profiling Method for SSH Clients and Servers
- [RDFP](https://github.com/yahoo/rdfp) - Zeek Remote desktop fingerprinting script based on [FATT](https://github.com/0x4D31/fatt) (Fingerprint All The Things)
- [FATT](https://github.com/0x4D31/fatt) - A pyshark based script for extracting network metadata and fingerprints from pcap files and live network traffic
- [FingerprinTLS](https://github.com/LeeBrotherston/tls-fingerprinting) - A TLS fingerprinting method
- [Mercury](https://github.com/cisco/mercury) - Network fingerprinting and packet metadata capture
- [GQUIC Protocol Analyzer for Zeek](https://github.com/salesforce/GQUIC_Protocol_Analyzer)
- [Recog](https://github.com/rapid7/recog) - A framework for identifying products, services, operating systems, and hardware by matching fingerprints against data returned from various network probes

### Dataset

- [Mordor](https://github.com/Cyb3rWard0g/mordor) - Pre-recorded security events generated by simulated adversarial techniques in the form of JavaScript Object Notation (JSON) files. The data is categorized by platforms, adversary groups, tactics and techniques defined by the Mitre ATT&CK Framework.
- [SecRepo.com](https://www.secrepo.com)([github repo](https://github.com/sooshie/secrepo)) - Samples of security related data.
- [Boss of the SOC (BOTS) Dataset Version 1](https://github.com/splunk/botsv1)
- [Boss of the SOC (BOTS) Dataset Version 2](https://github.com/splunk/botsv2)
- [Boss of the SOC (BOTS) Dataset Version 3](https://github.com/splunk/botsv3)
- [EMBER](https://github.com/endgameinc/ember) ([paper](https://arxiv.org/abs/1804.04637)) - The EMBER dataset is a collection of features from PE files that serve as a benchmark dataset for researchers
- [theZoo](https://github.com/ytisf/theZoo) - A repository of LIVE malwares


### Resources

- [Huntpedia](docs/huntpedia.pdf) - Your Threat Hunting Knowledge Compendium
- [Hunt Evil](docs/hunt-evil.pdf) - Your Practical Guide to Threat Hunting
- [The Hunter's Handbook](docs/The-Hunters-Handbook.pdf) - Endgame's guide to adversary hunting
- [ThreatHunter-Playbook](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook) - A Threat hunter's playbook to aid the development of techniques and hypothesis for hunting campaigns.
- [The ThreatHunting Project](https://github.com/ThreatHuntingProject/ThreatHunting) - A great [collection of hunts](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts) and threat hunting resources.
- [CyberThreatHunting](https://github.com/A3sal0n/CyberThreatHunting) - A collection of resources for threat hunters.
- [Hunt-Detect-Prevent](https://github.com/MHaggis/hunt-detect-prevent) - Lists of sources and utilities to hunt, detect and prevent evildoers.
- [Alerting and Detection Strategy Framework](https://medium.com/@palantir/alerting-and-detection-strategy-framework-52dc33722df2)
- [Generating Hypotheses for Successful Threat Hunting](https://www.sans.org/reading-room/whitepapers/threats/generating-hypotheses-successful-threat-hunting-37172)
- [Expert Investigation Guide - Threat Hunting](https://github.com/Foundstone/ExpertInvestigationGuides/tree/master/ThreatHunting)
- [Active Directory Threat Hunting](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)
- [Threat Hunting for Fileless Malware](https://www.countercept.com/our-thinking/threat-hunting-for-fileless-malware/)
- [Windows Commands Abused by Attackers](http://blog.jpcert.or.jp/.s/2016/01/windows-commands-abused-by-attackers.html)
- [Deception-as-Detection](https://github.com/0x4D31/deception-as-detection) - Deception based detection techniques mapped to the MITRE’s ATT&CK framework.
- [On TTPs](http://ryanstillions.blogspot.com.au/2014/04/on-ttps.html)
- Hunting On The Cheap ([Slides](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492182404.pdf))
- [Threat Hunting Techniques - AV, Proxy, DNS and HTTP Logs](https://www.cyberhuntz.com/2016/08/threat-hunting-techniques-av-proxy-dns.html)
- [Detecting Malware Beacons Using Splunk](https://pleasefeedthegeek.wordpress.com/2012/12/20/detecting-malware-beacons-using-splunk/)
- [Data Science Hunting Funnel](http://www.austintaylor.io/network/traffic/threat/data/science/hunting/funnel/machine/learning/domain/expertise/2017/07/11/data-science-hunting-funnel/)
- [Use Python & Pandas to Create a D3 Force Directed Network Diagram](http://www.austintaylor.io/d3/python/pandas/2016/02/01/create-d3-chart-python-force-directed/)
- [Syscall Auditing at Scale](https://slack.engineering/syscall-auditing-at-scale-e6a3ca8ac1b8)
- [Catching attackers with go-audit and a logging pipeline](https://summitroute.com/blog/2016/12/25/Catching_attackers_with_go-audit_and_a_logging_pipeline/)
- [The Coventry Conundrum of Threat Intelligence](https://summitroute.com/blog/2015/06/10/the_conventry_conundrum_of_threat_intelligence/)
- [Signal the ATT&CK: Part 1](https://www.pwc.co.uk/issues/cyber-security-data-privacy/research/signal-att-and-ck-part-1.html) - Building a real-time threat detection capability with Tanium that focuses on documented adversarial techniques.
- SANS Summit Archives ([DFIR](https://www.sans.org/cyber-security-summit/archives/dfir), [Cyber Defense](https://www.sans.org/cyber-security-summit/archives/cyber-defense)) - Threat hunting, Blue Team and DFIR summit slides
- [Bro-Osquery](https://svs.informatik.uni-hamburg.de/publications/2018/2018-05-31-Haas-QueryCon-Bro-Osquery.pdf) - Large-Scale Host and Network Monitoring Using Open-Source Software
- [Threat Hunting with Jupyter Notebooks](https://posts.specterops.io/threat-hunting-with-jupyter-notebooks-part-1-your-first-notebook-9a99a781fde7)
- [How Dropbox Security builds tools for threat detection and incident response](https://dropbox.tech/security/how-dropbox-security-builds-better-tools-for-threat-detection-and-incident-response)
- [Introducing Event Query Language](https://www.elastic.co/blog/introducing-event-query-language)
- [The No Hassle Guide to Event Query Language (EQL) for Threat Hunting](https://www.varonis.com/blog/guide-no-hassle-eql-threat-hunting/) ([PDF](docs/varonis.com-EQLforThreatHunting.pdf))
- [Introducing the Funnel of Fidelity](https://posts.specterops.io/introducing-the-funnel-of-fidelity-b1bb59b04036) ([PDF](docs/specterops-IntroducingtheFunnelofFidelity.pdf))
- [Detection Spectrum](https://posts.specterops.io/detection-spectrum-198a0bfb9302) ([PDF](docs/specterops-DetectionSpectrum.pdf))
- [Capability Abstraction](https://posts.specterops.io/capability-abstraction-fbeaeeb26384) ([PDF](docs/specterops-CapabilityAbstraction.pdf))
- [Awesome YARA](https://github.com/InQuest/awesome-yara) - A curated list of awesome YARA rules, tools, and resources

#### Frameworks

- [MITRE ATT&CK](https://attack.mitre.org/wiki/Main_Page) - A curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s lifecycle and the platforms they are known to target.
- [MITRE CAR](https://car.mitre.org/wiki/Main_Page) - The Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the Adversary Tactics, Techniques, and Common Knowledge (ATT&CK™) adversary model.
- [Alerting and Detection Strategies Framework](https://github.com/palantir/alerting-detection-strategy-framework) - A framework for developing alerting and detection strategies.
- [A Simple Hunting Maturity Model](http://detect-respond.blogspot.com.au/2015/10/a-simple-hunting-maturity-model.html) - The Hunting Maturity Model describes five levels of organizational hunting capability, ranging from HMM0 (the least capability) to HMM4 (the most).
- [The Pyramic of Pain](http://detect-respond.blogspot.com.au/2013/03/the-pyramid-of-pain.html) - The relationship between the types of indicators you might use to detect an adversary's activities and how much pain it will cause them when you are able to deny those indicators to them.
- [A Framework for Cyber Threat Hunting](docs/Framework-for-Threat-Hunting-Whitepaper.pdf)
- [The PARIS Model](http://threathunter.guru/blog/the-paris-model/) - A model for threat hunting.
- [Cyber Kill Chain](https://www.lockheedmartin.com/us/what-we-do/aerospace-defense/cyber/cyber-kill-chain.html) - It is part of the Intelligence Driven Defense® model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.
- [The DML Model](http://ryanstillions.blogspot.com.au/2014/04/the-dml-model_21.html) - The Detection Maturity Level (DML) model is a capability maturity model for referencing ones maturity in detecting cyber attacks.
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OSSEM](https://github.com/hunters-forge/OSSEM) (Open Source Security Events Metadata) - A community-led project that focuses on the documentation and standardization of security event logs from diverse data sources and operating systems

#### DNS

- [Detecting DNS Tunneling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [Hunting the Known Unknowns (with DNS)](https://www.splunk.com/pdfs/events/govsummit/hunting_the_known_unknowns_with_DNS.pdf)
- [Detecting dynamic DNS domains in Splunk](https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html)
- [Random Words on Entropy and DNS](https://www.splunk.com/blog/2015/10/01/random-words-on-entropy-and-dns.html)
- [Tracking Newly Registered Domains](https://isc.sans.edu/diary/Tracking+Newly+Registered+Domains/23127)
- [Suspicious Domains Tracking Dashboard](https://isc.sans.edu/forums/diary/Suspicious+Domains+Tracking+Dashboard/23046/)
- [Proactive Malicious Domain Search](https://isc.sans.edu/forums/diary/Proactive+Malicious+Domain+Search/23065/)
- [DNS is NOT Boring](https://www.first.org/resources/papers/conf2017/DNS-is-NOT-Boring-Using-DNS-to-Expose-and-Thwart-Attacks.pdf) - Using DNS to Expose and Thwart Attacks
- [Actionable Detects](https://prezi.com/vejpnxkm85ih/actionable-detects-dns-keynote/) - Blue Team Tactics

#### Command and Control

- [Command-and-control Malware Traffic Playbook](https://www.demisto.com/command-control-malware-traffic-playbook/)
- [How to Hunt Command & Control Channels Using Bro IDS and RITA](https://www.blackhillsinfosec.com/how-to-hunt-command-and-control-channels-using-bro-ids-and-rita/)
- [Detect Beaconing with Flare, Elastic Stack, and Intrusion Detection Systems](http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/)
- [Rise of Legitimate Services for Backdoor Command and Control](docs/legit-services.pdf)

#### Osquery

- [osquery Across the Enterprise](https://medium.com/@palantir/osquery-across-the-enterprise-3c3c9d13ec55)
- [osquery for Security — Part 1](https://medium.com/@clong/osquery-for-security-b66fffdf2daf)
- [osquery for Security — Part 2](https://medium.com/@clong/osquery-for-security-part-2-2e03de4d3721) - Advanced osquery functionality, File integrity monitoring, process auditing, and more.
- [Tracking a stolen code-signing certificate with osquery](https://blog.trailofbits.com/2017/10/10/tracking-a-stolen-code-signing-certificate-with-osquery/)
- [Monitoring macOS hosts with osquery](https://blog.kolide.com/monitoring-macos-hosts-with-osquery-ba5dcc83122d)
- [Kolide's Blog](https://blog.kolide.com/)
- [The osquery Extensions Skunkworks Project](https://github.com/trailofbits/presentations/tree/master/Osquery%20Extensions)

#### Windows

- [Threat Hunting via Windows Event Logs](https://www.sans.org/summit-archives/file/summit-archive-1524493093.pdf)
- [Windows Logging Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets/)
- [Active Directory Threat Hunting](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)
- [Windows Hunting](https://github.com/beahunt3r/Windows-Hunting) - A collection of Windows hunting queries
- [Windows Commands Abused by Attackers](https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html)
- [JPCERT - Detecting Lateral Movement through Tracking Event Logs](https://blogs.jpcert.or.jp/en/2017/12/research-report-released-detecting-lateral-movement-through-tracking-event-logs-version-2.html)
    - [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

##### Sysmon

- [Splunking the Endpoint: Threat Hunting with Sysmon](https://medium.com/@haggis_m/splunking-the-endpoint-threat-hunting-with-sysmon-9dd956e3e1bd)
    - [Hunting with Sysmon](https://medium.com/@haggis_m/hunting-with-sysmon-38de012e62e6)
- [Threat Hunting with Sysmon: Word Document with Macro](http://www.syspanda.com/index.php/2017/10/10/threat-hunting-sysmon-word-document-macro/)
- Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK
    - [Part I (Event ID 7)](https://cyberwardog.blogspot.com.au/2017/03/chronicles-of-threat-hunter-hunting-for.html)
    - [Part II (Event ID 10)](https://cyberwardog.blogspot.com.au/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)
- Advanced Incident Detection and Threat Hunting using Sysmon (and Splunk) ([botconf 2016 Slides](https://www.botconf.eu/wp-content/uploads/2016/11/PR12-Sysmon-UELTSCHI.pdf), [FIRST 2017 Slides](https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf))
- [The Sysmon and Threat Hunting Mimikatz wiki for the blue team](https://www.peerlyst.com/posts/the-sysmon-and-threat-hunting-mimikatz-wiki-for-the-blue-team-guurhart)
- [Splunkmon — Taking Sysmon to the Next Level](https://www.crypsisgroup.com/wp-content/uploads/2017/07/CG_WhitePaper_Splunkmon_1216-1.pdf)
- [Sysmon Threat Detection Guide](https://www.varonis.com/blog/sysmon-threat-detection-guide/) ([PDF](docs/varonis.com-SysmonThreatAnalysisGuide.pdf))

##### PowerShell

- Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science ([Paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science-wp.pdf), [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science.pdf))
- [Hunting the Known Unknowns (With PowerShell)](https://conf.splunk.com/files/2016/slides/hunting-the-known-unknowns-the-powershell-edition.pdf)
- [HellsBells, Let's Hunt PowerShells!](https://www.splunk.com/blog/2017/07/06/hellsbells-lets-hunt-powershells.html)
- [Hunting for PowerShell Using Heatmaps](https://medium.com/@jshlbrd/hunting-for-powershell-using-heatmaps-69b70151fa5d)

#### Fingerprinting

- [JA3: SSL/TLS Client Fingerprinting for Malware Detection](https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41)
- [TLS Fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)
- [HASSH - a profiling method for SSH Clients and Servers](https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c)
    - [HASSH @BSides Canberra 2019 - Slides](https://github.com/benjeems/Presentations/blob/master/BSides%202019%20%20-%20HASSH%20-%20a%20Profiling%20Method%20for%20SSH%20Clients%20and%20Servers.pdf)
- [Finding Evil on the Network Using JA3/S and HASSH](https://engineering.salesforce.com/finding-evil-on-the-network-using-ja3-s-and-hassh-11431a8606e4)
- [RDP Fingerprinting - Profiling RDP Clients with JA3 and RDFP](https://medium.com/@0x4d31/rdp-client-fingerprinting-9e7ac219f7f4)
- [Effective TLS Fingerprinting Beyond JA3](https://www.ntop.org/ndpi/effective-tls-fingerprinting-beyond-ja3/)
- [TLS Fingerprinting in the Real World](https://blogs.cisco.com/security/tls-fingerprinting-in-the-real-world)
- [HTTP Client Fingerprinting Using SSL Handshake Analysis](https://www.ssllabs.com/projects/client-fingerprinting/) (source code: [mod_sslhaf](https://github.com/ssllabs/sslhaf)
- [TLS fingerprinting - Smarter Defending & Stealthier Attacking](https://blog.squarelemon.com/tls-fingerprinting/)
- [JA3er](https://ja3er.com) - a DB of JA3 fingerprints
- [An Introduction to HTTP fingerprinting](https://www.net-square.com/httprint_paper.html)
- [TLS Fingerprints](https://tlsfingerprint.io/) collected from the University of Colorado Boulder campus network
- [The use of TLS in Censorship Circumvention](https://tlsfingerprint.io/static/frolov2019.pdf)
- [TLS Beyond the Browser: Combining End Host and Network Data to Understand Application Behavior](https://dl.acm.org/doi/pdf/10.1145/3355369.3355601)
- [HTTPS traffic analysis and client identification using passive SSL/TLS fingerprinting](https://link.springer.com/article/10.1186/s13635-016-0030-7)
- [Markov Chain Fingerprinting to Classify Encrypted Traffic](https://drakkar.imag.fr/IMG/pdf/1569811033.pdf)
- [HeadPrint: Detecting Anomalous Communications through Header-based Application Fingerprinting](https://www.conand.me/publications/bortolameotti-headprint-2020.pdf)

#### Research Papers

- [Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains](https://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf)
- [The Diamond Model of Intrusion Analysis](http://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [EXPOSURE: Finding Malicious Domains Using Passive DNS Analysis](https://www.cs.ucsb.edu/~chris/research/doc/ndss11_exposure.pdf)
- A Comprehensive Approach to Intrusion Detection Alert Correlation ([Paper](https://www.cs.ucsb.edu/~vigna/publications/2004_valeur_vigna_kruegel_kemmerer_TDSC_Correlation.pdf), [Dissertation](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.115.8310&rep=rep1&type=pdf))
- [On Botnets that use DNS for Command and Control](http://www.few.vu.nl/~herbertb/papers/feederbot_ec2nd11.pdf)
- [Intelligent, Automated Red Team Emulation](https://dl.acm.org/citation.cfm?id=2991111)
- [Machine Learning for Encrypted Malware Traffic Classification](https://dl.acm.org/doi/pdf/10.1145/3097983.3098163)

#### Blogs

- [David Bianco's Blog](https://detect-respond.blogspot.com)
- [DFIR and Threat Hunting Blog](http://findingbad.blogspot.com)
- [CyberWardog's Blog](https://medium.com/@Cyb3rWard0g) ([old](https://cyberwardog.blogspot.com))
- [Chris Sanders' Blog](https://chrissanders.org)
- [Kolide Blog](https://blog.kolide.com/)

### Videos

- [SANS Threat Hunting and IR Summit 2017](https://www.youtube.com/playlist?list=PLfouvuAjspTr95R60Kt7ZcoerR6tYoCLA)
- [SANS Threat Hunting and IR Summit 2016](https://www.youtube.com/playlist?list=PLfouvuAjspTokaa-LdUHqszL-KACkCsKT)
- [BotConf 2016 - Advanced Incident Detection and Threat Hunting using Sysmon and Splunk](https://www.youtube.com/watch?v=vv_VXntQTpE)
- [BSidesCharm 2017 - Detecting the Elusive: Active Directory Threat Hunting](https://www.youtube.com/watch?v=9Uo7V9OUaUw)
- [BSidesAugusta 2017 - Machine Learning Fueled Cyber Threat Hunting](https://www.youtube.com/watch?v=c-c-IQ5pFXw)
- [Toppling the Stack: Outlier Detection for Threat Hunters](https://www.youtube.com/watch?v=7q7GGg-Ws9s)
- [BSidesPhilly 2017 - Threat Hunting: Defining the Process While Circumventing Corporate Obstacles](https://www.youtube.com/watch?v=bDdsGBCUa8I)
- [Black Hat 2017 - Revoke-Obfuscation: PowerShell Obfuscation Detection (And Evasion) Using Science](https://www.youtube.com/watch?v=x97ejtv56xw)
- [DefCon 25 - MS Just Gave the Blue Team Tactical Nukes](https://www.youtube.com/watch?v=LUtluTaEAUU)
- [BSides London 2017 - Hunt or be Hunted](https://www.youtube.com/watch?v=19H7j_sZcKc)
- [SecurityOnion 2017 - Pivoting Effectively to Catch More Bad Guys](https://www.youtube.com/watch?v=_QVhMPGtIeU)
- [SkyDogCon 2016 - Hunting: Defense Against The Dark Arts](https://www.youtube.com/watch?v=mKxGulV2Z74)
- [BSidesAugusta 2017 - Don't Google 'PowerShell Hunting'](https://www.youtube.com/watch?v=1mfVPLPxKTc)
- [BSidesAugusta 2017 - Hunting Adversaries w Investigation Playbooks & OpenCNA](https://www.youtube.com/watch?v=8qM-DnmHNv8)
- [Visual Hunting with Linked Data](https://www.youtube.com/watch?v=98MrgfTFeMo)
- [RVAs3c - Pyramid of Pain: Intel-Driven Detection/Response to Increase Adversary's Cost](https://www.youtube.com/watch?v=zlAWbdSlhaQ)
- [BSidesLV 2016 - Hunting on the Endpoint w/ Powershell](https://www.youtube.com/watch?v=2MrrOxsJk_M)
- [Derbycon 2015 - Intrusion Hunting for the Masses A Practical Guide](https://www.youtube.com/watch?v=MUUseTJp3jM)
- [BSides DC 2016 - Practical Cyborgism: Getting Start with Machine Learning for Incident Detection](https://www.youtube.com/watch?v=2FvP7nwb2UE&feature=youtu.be)
- [SANS Webcast 2018 - What Event Logs? Part 1: Attacker Tricks to Remove Event Logs](https://www.youtube.com/watch?v=7JIftAw8wQY)
- [Profiling And Detecting All Things SSL With JA3](https://www.youtube.com/watch?v=oprPu7UIEuk)
- [ACoD 2019 - HASSH SSH Client/Server Profiling](https://www.youtube.com/watch?v=kG-kenOypLk)
- [QueryCon 2018](https://www.youtube.com/playlist?list=PLlSdCcsTOu5STvaoPlr-PJE-zbYmlAGrX) - An annual conference for the osquery open-source community ([querycon.io](https://querycon.io))
- [Visual Hunting with Linked Data Graphs](https://www.youtube.com/watch?v=EpK7MkWCh1I)
- [SecurityOnion Con 2018 - Introduction to Data Analysis](https://www.youtube.com/watch?v=A6hBoeSNJJw)

### Trainings

- [SANS SEC555](https://www.sans.org/course/siem-with-tactical-analytics) - SIEM with Tactical Analytics.
- [SpecterOps Adversary Tactics: PowerShell](https://github.com/specterops/at-ps) (FREE)
- [SpecterOps Adversary Tactics: Detection](https://specterops.io/how-we-help/training-offerings/adversary-tactics-detection)
- [eLearnSecurity THP](https://www.elearnsecurity.com/course/threat_hunting_professional/) - Threat Hunting Professional


### Twitter

- ["Awesome Detection" Twitter List](https://twitter.com/0x4d31/lists/awesome-detection) - Security guys who tweet about threat detection, hunting, DFIR, and red teaming

## Threat Simulation

A curated list of awesome adversary simulation resources

### Tools

- [MITRE CALDERA](https://github.com/mitre/caldera) - An automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks.
- [APTSimulator](https://github.com/NextronSystems/APTSimulator) - A Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework.
- [Network Flight Simulator](https://github.com/alphasoc/flightsim) - flightsim is a lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility.
- [Metta](https://github.com/uber-common/metta) - A security preparedness tool to do adversarial simulation.
- [Red Team Automation (RTA)](https://github.com/endgameinc/RTA) - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.
- [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter) - Payload Generation Framework.
- [CACTUSTORCH](https://github.com/mdsecactivebreach/CACTUSTORCH) - Payload Generation for Adversary Simulations.
- [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire) - A modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events.
- [Empire](https://github.com/EmpireProject/Empire)([website](http://www.powershellempire.com)) - A PowerShell and Python post-exploitation agent.
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/) - A PowerShell Post-Exploitation Framework.
- [RedHunt-OS](https://github.com/redhuntlabs/RedHunt-OS) - A Virtual Machine for Adversary Emulation and Threat Hunting. RedHunt aims to be a one stop shop for all your threat emulation and threat hunting needs by integrating attacker's arsenal as well as defender's toolkit to actively identify the threats in your environment.
- [Infection Monkey](https://github.com/guardicore/monkey) - An open source Breach and Attack Simulation (BAS) tool that assesses the resiliency of private and public cloud environments to post-breach attacks and lateral movement.

### Resources

- [MITRE's Adversary Emulation Plans](https://attack.mitre.org/wiki/Adversary_Emulation_Plans)
- [Awesome Red Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming) - A list of awesome red teaming resources
- [Red-Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki) - Wiki to collect Red Team infrastructure hardening resources.
- [Payload Generation using SharpShooter](https://www.mdsec.co.uk/2018/03/payload-generation-using-sharpshooter/)
- [SpecterOps Blog](https://posts.specterops.io/)
    - [Threat Hunting](https://posts.specterops.io/tagged/threat-hunting)
- [Advanced Threat Tactics](https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes/) - A free course on red team operations and adversary simulations.
- [Signal the ATT&CK: Part 1](https://www.pwc.co.uk/issues/cyber-security-data-privacy/research/signal-att-and-ck-part-1.html) - Modelling APT32 in CALDERA 
- [Red Teaming/Adversary Simulation Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit) - A collection of open source and commercial tools that aid in red team operations.
- [C2 Matrix](https://www.thec2matrix.com/matrix) ([Google Sheets](https://docs.google.com/spreadsheets/d/1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc))

## Contribute

Contributions welcome! Read the [contribution guidelines](CONTRIBUTING.md) first.


## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0)

To the extent possible under law, Adel &#34;0x4D31&#34; Karimi has waived all copyright and
related or neighboring rights to this work.
