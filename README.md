# Awesome Threat Detection and Hunting
[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

> A curated list of awesome threat detection and hunting resources


## Contents

- [Threat Detection and Hunting](#threat-detection-and-hunting)
    - [Tools](#tools)
    - [Resources](#resources)
        - [Frameworks](#frameworks)
        - [Research Papers](#research-papers)
        - [Blogs](#blogs)
        - [DNS](#dns)
        - [Command and Control](#command-and-control)
        - [PowerShell](#powershell)
        - [Osquery](#osquery)
        - [Sysmon](#sysmon)
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
- [osquery](https://osquery.io/) - An operating system instrumentation framework for Windows, OS X (macOS), Linux, and FreeBSD. It exposes an operating system as a high-performance relational database.
- [osquery-configuration](https://github.com/palantir/osquery-configuration) - A repository for using osquery for incident detection and response.
- [DetectionLab](https://github.com/clong/DetectionLab/) - Vagrant & Packer scripts to build a lab environment complete with security tooling and logging best practices.
- [Sysmon-DFIR](https://github.com/MHaggis/sysmon-dfir) - Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
- [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) - Sysmon configuration file template with default high-quality event tracing.
- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) - A repository of sysmon configuration modules. It also includes a [mapping](https://github.com/olafhartong/sysmon-modular/blob/master/attack_matrix/README.md) of Sysmon configurations to MITRE ATT&CK techniques.
- [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) - PowerShell Obfuscation Detection Framework.
- [Invoke-ATTACKAPI](https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI) - A PowerShell script to interact with the MITRE ATT&CK Framework via its own API.
- [Unfetter](https://github.com/unfetter-analytic/unfetter) - A reference implementation provides a framework for collecting events (process creation, network connections, Window Event Logs, etc.) from a client machine and performing CAR analytics to detect potential adversary activity.
- [NOAH](https://github.com/giMini/NOAH) - PowerShell No Agent Hunting.
- [PSHunt](https://github.com/Infocyte/PSHunt) - Powershell Threat Hunting Module.
- [Flare](https://github.com/austin-taylor/flare) - An analytical framework for network traffic and behavioral analytics.
- [go-audit](https://github.com/slackhq/go-audit) - An alternative to the auditd daemon that ships with many distros.
- [sqhunter](https://github.com/0x4D31/sqhunter) - A simple threat hunting tool based on osquery, Salt Open and Cymon API.
- [RedHunt-OS](https://github.com/redhuntlabs/RedHunt-OS) - A Virtual Machine for Adversary Emulation and Threat Hunting. RedHunt aims to be a one stop shop for all your threat emulation and threat hunting needs by integrating attacker's arsenal as well as defender's toolkit to actively identify the threats in your environment.

### Resources

- [Huntpedia](http://info.sqrrl.com/huntpedia) - Your Threat Hunting Knowledge Compendium
- [Hunt Evil](http://info.sqrrl.com/practical-threat-hunting) - Your Practical Guide to Threat Hunting
- [The Hunter's Handbook](https://cyber-edge.com/wp-content/uploads/2016/08/The-Hunters-Handbook.pdf) - Endgame's guide to adversary hunting
- [ThreatHunter-Playbook](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook) - A Threat hunter's playbook to aid the development of techniques and hypothesis for hunting campaigns.
- [The ThreatHunting Project](https://github.com/ThreatHuntingProject/ThreatHunting) - A great [collection of hunts](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts) and threat hunting resources.
- [CyberThreatHunting](https://github.com/A3sal0n/CyberThreatHunting) - A collection of resources for threat hunters.
- [Hunt-Detect-Prevent](https://github.com/MHaggis/hunt-detect-prevent) - Lists of sources and utilities to hunt, detect and prevent evildoers.
- [Alerting and Detection Strategy Framework](https://medium.com/@palantir/alerting-and-detection-strategy-framework-52dc33722df2)
- A Framework for Cyber Threat Hunting ([Part1](https://sqrrl.com/a-framework-for-cyber-threat-hunting-part-1-the-pyramid-of-pain/), [Part2](https://sqrrl.com/a-framework-for-cyber-threat-hunting-part-2-advanced-persistent-defense/), [Part3](https://sqrrl.com/a-framework-for-cyber-threat-hunting-part-3-the-value-of-hunting-ttps/))
- [Common Threat Hunting Techniques & Datasets](https://sqrrl.com/media/Common-Techniques-for-Hunting.pdf)
- [Generating Hypotheses for Successful Threat Hunting](https://www.sans.org/reading-room/whitepapers/threats/generating-hypotheses-successful-threat-hunting-37172)
- [Expert Investigation Guide - Threat Hunting](https://github.com/Foundstone/ExpertInvestigationGuides/tree/master/ThreatHunting)
- [Active Directory Threat Hunting](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)
- [Threat Hunting for Fileless Malware](https://www.countercept.com/our-thinking/threat-hunting-for-fileless-malware/)
- [Windows Commands Abused by Attackers](http://blog.jpcert.or.jp/.s/2016/01/windows-commands-abused-by-attackers.html)
- [Deception-as-Detection](https://github.com/0x4D31/deception-as-detection) - Deception based detection techniques mapped to the MITRE’s ATT&CK framework.
- [Deception, Breaches, and Going on the Offense to Seed the Hunt](https://sqrrl.com/deception-breaches-going-offense-seed-hunt/)
- [On TTPs](http://ryanstillions.blogspot.com.au/2014/04/on-ttps.html)
- [Situational-Awareness Driven Threat Hunting](https://sqrrl.com/situational-awareness-driven-threat-hunting/)
- Hunting On The Cheap ([Part 1: The Architecture](https://www.endgame.com/blog/technical-blog/hunting-cheap-part-1-architecture), [Part 2: Hunting On Networks](https://www.endgame.com/blog/technical-blog/hunting-networks-part-2-higher-order-patterns), [Part 3: Hunting On Hosts](https://www.endgame.com/blog/technical-blog/hunting-cheap-part-3-hunting-hosts), [Slides](https://files.sans.org/summit/Threat_Hunting_Incident_Response_Summit_2016/PDFs/Hunting-on-the-Cheap-Butler-Ahuja-Morris-Endgame.pdf))
- [Threat Hunting Techniques - AV, Proxy, DNS and HTTP Logs](http://www.brainfold.net/2016/08/threat-hunting-techniques-av-proxy-dns.html)
- [Detecting Malware Beacons Using Splunk](https://pleasefeedthegeek.wordpress.com/2012/12/20/detecting-malware-beacons-using-splunk/)
- [Flattened MITRE ATT&CK Matrix](https://docs.google.com/spreadsheets/d/1ljXt_ct2J7TuQ45KtvGppHwZUVF7lNxiaAKII6frhOs) - It contains all matrix categories mapped to techniques with examples of application by software or threat actor groups.
- [Data Science Hunting Funnel](http://www.austintaylor.io/network/traffic/threat/data/science/hunting/funnel/machine/learning/domain/expertise/2017/07/11/data-science-hunting-funnel/)
- [Use Python & Pandas to Create a D3 Force Directed Network Diagram](http://www.austintaylor.io/d3/python/pandas/2016/02/01/create-d3-chart-python-force-directed/)
- [Syscall Auditing at Scale](https://slack.engineering/syscall-auditing-at-scale-e6a3ca8ac1b8)
- [Catching attackers with go-audit and a logging pipeline](https://summitroute.com/blog/2016/12/25/Catching_attackers_with_go-audit_and_a_logging_pipeline/)
- [The Coventry Conundrum of Threat Intelligence](https://summitroute.com/blog/2015/06/10/the_conventry_conundrum_of_threat_intelligence/)
- [Signal the ATT&CK: Part 1](https://www.pwc.co.uk/issues/cyber-security-data-privacy/research/signal-att-and-ck-part-1.html) - Building a real-time threat detection capability with Tanium that focuses on documented adversarial techniques.

#### Frameworks

- [MITRE ATT&CK](https://attack.mitre.org/wiki/Main_Page) - A curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s lifecycle and the platforms they are known to target.
- [MITRE CAR](https://car.mitre.org/wiki/Main_Page) - The Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the Adversary Tactics, Techniques, and Common Knowledge (ATT&CK™) adversary model.
- [Alerting and Detection Strategies Framework](https://github.com/palantir/alerting-detection-strategy-framework) - A framework for developing alerting and detection strategies.
- [A Simple Hunting Maturity Model](http://detect-respond.blogspot.com.au/2015/10/a-simple-hunting-maturity-model.html) - The Hunting Maturity Model describes five levels of organizational hunting capability, ranging from HMM0 (the least capability) to HMM4 (the most).
- [The Pyramic of Pain](http://detect-respond.blogspot.com.au/2013/03/the-pyramid-of-pain.html) - The relationship between the types of indicators you might use to detect an adversary's activities and how much pain it will cause them when you are able to deny those indicators to them.
- [A Framework for Cyber Threat Hunting](http://sqrrl.com/media/Framework-for-Threat-Hunting-Whitepaper.pdf)
- [The PARIS Model](http://threathunter.guru/blog/the-paris-model/) - A model for threat hunting.
- [Cyber Kill Chain](https://www.lockheedmartin.com/us/what-we-do/aerospace-defense/cyber/cyber-kill-chain.html) - It is part of the Intelligence Driven Defense® model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.
- [The DML Model](http://ryanstillions.blogspot.com.au/2014/04/the-dml-model_21.html) - The Detection Maturity Level (DML) model is a capability maturity model for referencing ones maturity in detecting cyber attacks.
- [Endgame Hunt Cycle](http://pages.endgame.com/rs/627-YBU-612/images/Endgame%20Hunt%20Methodology%20POV%203.24.16.pdf)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Sigma](https://github.com/Neo23x0/sigma) - Generic Signature Format for SIEM Systems

#### Research Papers

- [Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains](https://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf)
- [The Diamond Model of Intrusion Analysis](http://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [EXPOSURE: Finding Malicious Domains Using Passive DNS Analysis](https://www.cs.ucsb.edu/~chris/research/doc/ndss11_exposure.pdf)
- A Comprehensive Approach to Intrusion Detection Alert Correlation ([Paper](https://www.cs.ucsb.edu/~vigna/publications/2004_valeur_vigna_kruegel_kemmerer_TDSC_Correlation.pdf), [Dissertation](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.115.8310&rep=rep1&type=pdf))
- [On Botnets that use DNS for Command and Control](http://www.few.vu.nl/~herbertb/papers/feederbot_ec2nd11.pdf)
- [Intelligent, Automated Red Team Emulation](https://dl.acm.org/citation.cfm?id=2991111)

#### Blogs

- [David Bianco's Blog](https://detect-respond.blogspot.com)
- [sqrrl Hunting Blog](https://sqrrl.com/blog/)
- [DFIR and Threat Hunting Blog](http://findingbad.blogspot.com)
- [CyberWardog's Blog](https://cyberwardog.blogspot.com)
- [Chris Sanders' Blog](https://chrissanders.org)

#### DNS

- [Leveraging DNS to Surface Attacker Activity](http://sqrrl.com/media/Webinar-Leveraging-DNS-Slides.pdf)
- [Detecting DNS Tunneling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [The Nuts and Bolts of Detecting DNS Tunneling](https://sqrrl.com/the-nuts-and-bolts-of-detecting-dns-tunneling/)
- [Hunting the Known Unknowns (with DNS)](https://www.splunk.com/pdfs/events/govsummit/hunting_the_known_unknowns_with_DNS.pdf)
- [Detecting dynamic DNS domains in Splunk](https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html)
- [Random Words on Entropy and DNS](https://www.splunk.com/blog/2015/10/01/random-words-on-entropy-and-dns.html)
- [Tracking Newly Registered Domains](https://isc.sans.edu/diary/Tracking+Newly+Registered+Domains/23127)
- [Suspicious Domains Tracking Dashboard](https://isc.sans.edu/forums/diary/Suspicious+Domains+Tracking+Dashboard/23046/)
- [Proactive Malicious Domain Search](https://isc.sans.edu/forums/diary/Proactive+Malicious+Domain+Search/23065/)

#### Command and Control

- [The Hunter's Den: Command and Control](https://sqrrl.com/the-hunters-den-command-and-control/)
- [Command-and-control Malware Traffic Playbook](https://www.demisto.com/command-control-malware-traffic-playbook/)
- [How to Hunt Command & Control Channels Using Bro IDS and RITA](https://www.blackhillsinfosec.com/how-to-hunt-command-and-control-channels-using-bro-ids-and-rita/)
- [Detect Beaconing with Flare, Elastic Stack, and Intrusion Detection Systems](http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/)
- [Rise of Legitimate Services for Backdoor Command and Control](https://anomali.cdn.rackfoundry.net/files/anomali-labs-reports/legit-services.pdf)

#### PowerShell

- Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science ([Paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science-wp.pdf), [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science.pdf))
- [Hunting the Known Unknowns (With PowerShell)](https://conf.splunk.com/files/2016/slides/hunting-the-known-unknowns-the-powershell-edition.pdf)
- [HellsBells, Let's Hunt PowerShells!](https://www.splunk.com/blog/2017/07/06/hellsbells-lets-hunt-powershells.html)
- [Hunting for PowerShell Using Heatmaps](https://medium.com/@jshlbrd/hunting-for-powershell-using-heatmaps-69b70151fa5d)

#### Osquery

- [osquery Across the Enterprise](https://medium.com/@palantir/osquery-across-the-enterprise-3c3c9d13ec55)
- [osquery for Security — Part 1](https://medium.com/@clong/osquery-for-security-b66fffdf2daf)
- [osquery for Security — Part 2](https://medium.com/@clong/osquery-for-security-part-2-2e03de4d3721) - Advanced osquery functionality, File integrity monitoring, process auditing, and more.
- [Tracking a stolen code-signing certificate with osquery](https://blog.trailofbits.com/2017/10/10/tracking-a-stolen-code-signing-certificate-with-osquery/)
- [Monitoring macOS hosts with osquery](https://blog.kolide.com/monitoring-macos-hosts-with-osquery-ba5dcc83122d)
- [Kolide's Blog](https://blog.kolide.com/)

#### Sysmon

- [Splunking the Endpoint: Threat Hunting with Sysmon](https://medium.com/@haggis_m/splunking-the-endpoint-threat-hunting-with-sysmon-9dd956e3e1bd)
    - [Hunting with Sysmon](https://medium.com/@haggis_m/hunting-with-sysmon-38de012e62e6)
- [Threat Hunting with Sysmon: Word Document with Macro](http://www.syspanda.com/index.php/2017/10/10/threat-hunting-sysmon-word-document-macro/)
- Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK
    - [Part I (Event ID 7)](https://cyberwardog.blogspot.com.au/2017/03/chronicles-of-threat-hunter-hunting-for.html)
    - [Part II (Event ID 10)](https://cyberwardog.blogspot.com.au/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)
- Advanced Incident Detection and Threat Hunting using Sysmon (and Splunk) ([botconf 2016 Slides](https://www.botconf.eu/wp-content/uploads/2016/11/PR12-Sysmon-UELTSCHI.pdf), [FIRST 2017 Slides](https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf))
- [The Sysmon and Threat Hunting Mimikatz wiki for the blue team](https://www.peerlyst.com/posts/the-sysmon-and-threat-hunting-mimikatz-wiki-for-the-blue-team-guurhart)
- [Splunkmon — Taking Sysmon to the Next Level](https://www.crypsisgroup.com/wp-content/uploads/2017/07/CG_WhitePaper_Splunkmon_1216-1.pdf)


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


### Trainings

- [Threat Hunting Academy](https://threathunting.org)
- [SANS FOR508](https://www.sans.org/course/advanced-incident-response-threat-hunting-training) - Advanced Digital Forensics, Incident Response, and Threat Hunting.
- [eLearnSecurity THP](https://www.elearnsecurity.com/course/threat_hunting_professional/) - Threat Hunting Professional


### Twitter

- ["Awesome Detection" Twitter List](https://twitter.com/0x4d31/lists/awesome-detection) - Security guys who tweet about threat detection, hunting, DFIR, and red teaming
- ["Awesome Detection" Collection](https://twitter.com/0x4d31/timelines/952125848508772353) - A collection of tweets about threat detection, hunting, DFIR, and read teaming techniques that can help you create detection logics.
- [Top #infosec Twitter Accounts](https://sqrrl.com/top-infosec-twitter-accounts/) (From a Threat Hunter’s Perspective)


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

### Resources

- [MITRE's Adversary Emulation Plans](https://attack.mitre.org/wiki/Adversary_Emulation_Plans)
- [Awesome Red Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming) - A list of awesome red teaming resources
- [Red-Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki) - Wiki to collect Red Team infrastructure hardening resources.
- [Payload Generation using SharpShooter](https://www.mdsec.co.uk/2018/03/payload-generation-using-sharpshooter/)
- [SpecterOps Blog](https://posts.specterops.io/)
- [Advanced Threat Tactics](https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes/) - A free course on red team operations and adversary simulations.
- [Signal the ATT&CK: Part 1](https://www.pwc.co.uk/issues/cyber-security-data-privacy/research/signal-att-and-ck-part-1.html) - Modelling APT32 in CALDERA 
- [Introducing Endgame Red Team Automation](https://www.endgame.com/blog/technical-blog/introducing-endgame-red-team-automation)
- [Red Teaming/Adversary Simulation Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit) - A collection of open source and commercial tools that aid in red team operations.

## Contribute

Contributions welcome! Read the [contribution guidelines](CONTRIBUTING.md) first.


## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0)

To the extent possible under law, Adel &#34;0x4D31&#34; Karimi has waived all copyright and
related or neighboring rights to this work.
