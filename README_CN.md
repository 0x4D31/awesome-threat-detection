# 威胁检测与威胁狩猎大合集
[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

> 威胁检测、威胁狩猎资源的资源合辑

## 目录

- [威胁检测与威胁狩猎](#threat-detection-and-hunting)
    - [工具](#tools)
    - [资源](#resources)
        - [框架](#frameworks)
        - [研究论文](#research-papers)
        - [博客](#blogs)
        - [DNS](#dns)
        - [C&C](#command-and-control)
        - [PowerShell](#powershell)
        - [Osquery](#osquery)
        - [Sysmon](#sysmon)
    - [视频](#videos)
    - [培训](#trainings)
    - [Twitter](#twitter)
- [贡献](#contribute)
- [许可证](#license)


## Threat Detection and Hunting


### Tools

- [HELK](https://github.com/Cyb3rWard0g/HELK) - 具有高级分析能力的威胁狩猎 ELK (Elasticsearch, Logstash, Kibana)
- [osquery](https://osquery.io/) - 用于 Windows、OS X（macOS）、Linux 和 FreeBSD 的操作系统工具框架，视操作系统为一个高性能的关系数据库
- [osquery-configuration](https://github.com/palantir/osquery-configuration) -  使用 osquery 进行事件检测和响应的项目
- [DetectionLab](https://github.com/clong/DetectionLab/) - 使用 Vagrant&Packer 脚本来构建实验室环境，包含安全工具和最佳实践的记录
- [Sysmon-DFIR](https://github.com/MHaggis/sysmon-dfir) - 如何利用微软Sysmon检测恶意事件相关的资源、配置
- [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) - 附带有默认高质量事件跟踪的 Sysmon 配置文件模板
- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) - sysmon 配置的存储库，还包括 Sysmon 配置到 MITRE ATT&CK 的[映射](https://github.com/olafhartong/sysmon-modular/blob/master/attack_matrix/README.md)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - 高度便携的检测测试映射到 Mitre ATT&CK 框架
- [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) - PowerShell 混淆检测框架
- [Invoke-ATTACKAPI](https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI) - 通过自己的 API 与 MITRE ATT&CK 框架进行交互的 PowerShell 脚本
- [MITRE CALDERA](https://github.com/mitre/caldera) - 在 Windows 企业网络中攻击投递后的自动对手仿真系统
- [Unfetter](https://github.com/unfetter-analytic/unfetter) - 实现一个用于从客户机收集事件（进程创建、网络连接、Windows 事件日志等），执行 CAR 分析以检测潜在的攻击活动的框架
- [NOAH](https://github.com/giMini/NOAH) - 无 Agent 的 PowerShell 狩猎
- [PSHunt](https://github.com/Infocyte/PSHunt) - PowerShell 威胁狩猎模块
- [Flare](https://github.com/austin-taylor/flare) - 用于网络流量和行为分析的分析框架
- [go-audit](https://github.com/slackhq/go-audit) - 许多发行版附带的守护进程的替代方案
- [sqhunter](https://github.com/0x4D31/sqhunter) - 基于 osquery、Salt Open、Cymon API 的简单威胁狩猎工具

### Resources

- [Huntpedia](http://info.sqrrl.com/huntpedia) - 威胁狩猎知识概要
- [Hunt Evil](http://info.sqrrl.com/practical-threat-hunting) - 威胁狩猎使用指南
- [The Hunter's Handbook](https://cyber-edge.com/wp-content/uploads/2016/08/The-Hunters-Handbook.pdf) - 威胁狩猎指南
- [ThreatHunter-Playbook](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook) - 威胁猎手指南，帮助发展威胁狩猎的技术与假设
- [The ThreatHunting Project](https://github.com/ThreatHuntingProject/ThreatHunting) - 一个[威胁狩猎资源集合](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts)
- [CyberThreatHunting](https://github.com/A3sal0n/CyberThreatHunting) - 威胁猎手的资源集合
- [Hunt-Detect-Prevent](https://github.com/MHaggis/hunt-detect-prevent) - 狩猎、检测与预防利用的清单
- [报警与检测策略框架](https://medium.com/@palantir/alerting-and-detection-strategy-framework-52dc33722df2)
- 网络威胁狩猎框架 ([Part1](https://sqrrl.com/a-framework-for-cyber-threat-hunting-part-1-the-pyramid-of-pain/), [Part2](https://sqrrl.com/a-framework-for-cyber-threat-hunting-part-2-advanced-persistent-defense/), [Part3](https://sqrrl.com/a-framework-for-cyber-threat-hunting-part-3-the-value-of-hunting-ttps/))
- [常见威胁狩猎技术与数据集](https://sqrrl.com/media/Common-Techniques-for-Hunting.pdf)
- [为成功的威胁狩猎生成假设](https://www.sans.org/reading-room/whitepapers/threats/generating-hypotheses-successful-threat-hunting-37172)
- [专家调查指南 - 威胁狩猎](https://github.com/Foundstone/ExpertInvestigationGuides/tree/master/ThreatHunting)
- [活动目录威胁狩猎](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)
- [使用威胁狩猎寻找无文件恶意软件](https://www.countercept.com/our-thinking/threat-hunting-for-fileless-malware/)
- [被攻击者滥用的 Windows 命令](http://blog.jpcert.or.jp/.s/2016/01/windows-commands-abused-by-attackers.html)
- [欺骗与检测](https://github.com/0x4D31/deception-as-detection) - 基于欺骗的检测，并映射到 MITRE 的 ATT&CK 框架
- [欺骗与威胁狩猎](https://sqrrl.com/deception-breaches-going-offense-seed-hunt/)
- [TTP](http://ryanstillions.blogspot.com.au/2014/04/on-ttps.html)
- [情景驱动的威胁狩猎](https://sqrrl.com/situational-awareness-driven-threat-hunting/)
- 廉价狩猎 ([Part 1: 架构](https://www.endgame.com/blog/technical-blog/hunting-cheap-part-1-architecture), [Part 2: 网络狩猎](https://www.endgame.com/blog/technical-blog/hunting-networks-part-2-higher-order-patterns), [Part 3: 狩猎主机](https://www.endgame.com/blog/technical-blog/hunting-cheap-part-3-hunting-hosts), [Slides](https://files.sans.org/summit/Threat_Hunting_Incident_Response_Summit_2016/PDFs/Hunting-on-the-Cheap-Butler-Ahuja-Morris-Endgame.pdf))
- [威胁狩猎技术 - 反病毒、代理、DNS 和 HTTP 日志](http://www.brainfold.net/2016/08/threat-hunting-techniques-av-proxy-dns.html)
- [使用 Splunk 检测恶意软件](https://pleasefeedthegeek.wordpress.com/2012/12/20/detecting-malware-beacons-using-splunk/)
- [展开 MITRE ATT&CK Matrix](https://docs.google.com/spreadsheets/d/1ljXt_ct2J7TuQ45KtvGppHwZUVF7lNxiaAKII6frhOs) - 其中所有矩阵类别都有相关技术，以及软件的示例程序
- [数据科学狩猎漏斗](http://www.austintaylor.io/network/traffic/threat/data/science/hunting/funnel/machine/learning/domain/expertise/2017/07/11/data-science-hunting-funnel/)
- [使用 Python 和 Pandas 创建 D3 Force Directed Network 图表](http://www.austintaylor.io/d3/python/pandas/2016/02/01/create-d3-chart-python-force-directed/)
- [系统调用审计](https://slack.engineering/syscall-auditing-at-scale-e6a3ca8ac1b8)
- [通过审计和日志管道来捕获攻击者](https://summitroute.com/blog/2016/12/25/Catching_attackers_with_go-audit_and_a_logging_pipeline/)
- [威胁情报的考文垂难题](https://summitroute.com/blog/2015/06/10/the_conventry_conundrum_of_threat_intelligence/)

#### Frameworks

- [MITRE ATT&CK](https://attack.mitre.org/wiki/Main_Page) - 网络攻击行为的知识库与模型，对应对手生命周期的各个阶段以及各个平台
- [MITRE CAR](https://car.mitre.org/wiki/Main_Page) - Cyber Analytics Repository (CAR) 是 MITRE 基于 ATT&CK™（对手战术、技术和常识）模型开发的分析知识库
- [Alerting and Detection Strategies Framework](https://github.com/palantir/alerting-detection-strategy-framework) - 开发报警和检测策略的框架
- [A Simple Hunting Maturity Model](http://detect-respond.blogspot.com.au/2015/10/a-simple-hunting-maturity-model.html) - 狩猎成熟度模型描述了从 HMM0（最低能力）到 HMM4（最高能力）五个层次的狩猎能力
- [The Pyramic of Pain](http://detect-respond.blogspot.com.au/2013/03/the-pyramid-of-pain.html) - 检测攻击者的活动和威胁指标的关系
- [网络威胁狩猎框架](http://sqrrl.com/media/Framework-for-Threat-Hunting-Whitepaper.pdf)
- [PARIS 模型](http://threathunter.guru/blog/the-paris-model/) - 威胁狩猎模型
- [Cyber Kill Chain](https://www.lockheedmartin.com/us/what-we-do/aerospace-defense/cyber/cyber-kill-chain.html) - 智能驱动防御（Intelligence Driven Defense®）的的一部分，用于识别和阻止网络入侵活动。该模型确定攻击者必须完成才能实现其目标的动作
- [The DML Model](http://ryanstillions.blogspot.com.au/2014/04/the-dml-model_21.html) - 检测成熟度等级(DML)模型是一个引用成熟度检测网络攻击能力成熟度的模型
- [Endgame Hunt Cycle](http://pages.endgame.com/rs/627-YBU-612/images/Endgame%20Hunt%20Methodology%20POV%203.24.16.pdf)
- [NIST 网络安全框架](https://www.nist.gov/cyberframework)

#### Research Papers

- [通过分析攻击者的活动与入侵杀伤链得到的情报驱动计算机网络防御](https://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf)
- [入侵分析的钻石模型](http://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [EXPOSURE: 使用 Passive DNS 分析查找恶意域名](https://www.cs.ucsb.edu/~chris/research/doc/ndss11_exposure.pdf)
- 综合入侵检测报警关联方法 ([Paper](https://www.cs.ucsb.edu/~vigna/publications/2004_valeur_vigna_kruegel_kemmerer_TDSC_Correlation.pdf), [Dissertation](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.115.8310&rep=rep1&type=pdf))
- [使用 DNS 进行 C&C 的僵尸网络](http://www.few.vu.nl/~herbertb/papers/feederbot_ec2nd11.pdf)
- [智能的、自动的红队模拟工具](https://dl.acm.org/citation.cfm?id=2991111)

#### Blogs

- [David Bianco 的博客](https://detect-respond.blogspot.com)
- [sqrrl Hunting 的博客](https://sqrrl.com/blog/)
- [DFIR 和威胁狩猎博客](http://findingbad.blogspot.com)
- [CyberWardog 的博客](https://cyberwardog.blogspot.com)
- [Chris Sanders 的博客](https://chrissanders.org)

#### DNS

- [利用 DNS 到攻击行为](http://sqrrl.com/media/Webinar-Leveraging-DNS-Slides.pdf)
- [检测 DNS 隧道](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [检测 DNS 隧道的核心](https://sqrrl.com/the-nuts-and-bolts-of-detecting-dns-tunneling/)
- [使用 DNS 狩猎未知域名](https://www.splunk.com/pdfs/events/govsummit/hunting_the_known_unknowns_with_DNS.pdf)
- [使用 Splunk 检测动态 DNS 域名](https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html)
- [熵与 DNS 中的 Random Words](https://www.splunk.com/blog/2015/10/01/random-words-on-entropy-and-dns.html)
- [跟踪新注册的域名](https://isc.sans.edu/diary/Tracking+Newly+Registered+Domains/23127)
- [可疑域名跟踪展板](https://isc.sans.edu/forums/diary/Suspicious+Domains+Tracking+Dashboard/23046/)
- [主动恶意域名搜索](https://isc.sans.edu/forums/diary/Proactive+Malicious+Domain+Search/23065/)

#### Command and Control

- [猎人书房：命令与控制](https://sqrrl.com/the-hunters-den-command-and-control/)
- [命令与控制：恶意软件流量工具书](https://www.demisto.com/command-control-malware-traffic-playbook/)
- [如何使用 Bro IDS 和 RITA 来搜索 C&C 信道](https://www.blackhillsinfosec.com/how-to-hunt-command-and-control-channels-using-bro-ids-and-rita/)
- [使用 Flare、Elastic Stack 和入侵检测系统检测 Beaconing](http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/)
- [后门 C&C 合法服务的兴起](https://anomali.cdn.rackfoundry.net/files/anomali-labs-reports/legit-services.pdf)

#### PowerShell

- 去混淆：科学使用 PowerShell 进行混淆检测 ([Paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science-wp.pdf), [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science.pdf))
- [PowerShell 狩猎未知域名](https://conf.splunk.com/files/2016/slides/hunting-the-known-unknowns-the-powershell-edition.pdf)
- [地狱之锤，狩猎 PowerShell！](https://www.splunk.com/blog/2017/07/06/hellsbells-lets-hunt-powershells.html)
- [使用热力图狩猎 PowerShell](https://medium.com/@jshlbrd/hunting-for-powershell-using-heatmaps-69b70151fa5d)

#### Osquery

- [osquery 企业访问](https://medium.com/@palantir/osquery-across-the-enterprise-3c3c9d13ec55)
- [osquery for Security — Part 1](https://medium.com/@clong/osquery-for-security-b66fffdf2daf)
- [osquery for Security — Part 2](https://medium.com/@clong/osquery-for-security-part-2-2e03de4d3721) - 高级 osquery 功能：文件完整性监视、进程审计等
- [使用 osquery 跟踪被盗代码签名证书](https://blog.trailofbits.com/2017/10/10/tracking-a-stolen-code-signing-certificate-with-osquery/)
- [使用 osquery 监视 macOS 主机](https://blog.kolide.com/monitoring-macos-hosts-with-osquery-ba5dcc83122d)
- [Kolide 的博客](https://blog.kolide.com/)

#### Sysmon

- [Splunking 终端：使用 Sysmon 进行威胁狩猎](https://medium.com/@haggis_m/splunking-the-endpoint-threat-hunting-with-sysmon-9dd956e3e1bd)
    - [使用 Sysmon 狩猎](https://medium.com/@haggis_m/hunting-with-sysmon-38de012e62e6)
- [使用 Sysmon 进行威胁狩猎：带有宏的 Word 文档](http://www.syspanda.com/index.php/2017/10/10/threat-hunting-sysmon-word-document-macro/)
- 威胁猎手编年史：用 Sysmon 和 ELK 在内存中检索Mimikatz
    - [Part I (Event ID 7)](https://cyberwardog.blogspot.com.au/2017/03/chronicles-of-threat-hunter-hunting-for.html)
    - [Part II (Event ID 10)](https://cyberwardog.blogspot.com.au/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)
- 使用 Sysmon 和 Splunk 进行高级事件检测和威胁狩猎 ([botconf 2016 Slides](https://www.botconf.eu/wp-content/uploads/2016/11/PR12-Sysmon-UELTSCHI.pdf), [FIRST 2017 Slides](https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf))
- [蓝队的 Sysmon 和 Mimikatz 的威胁狩猎 Wiki](https://www.peerlyst.com/posts/the-sysmon-and-threat-hunting-mimikatz-wiki-for-the-blue-team-guurhart)
- [Splunkmon — 将 Sysmon 带入下一个 Level](https://www.crypsisgroup.com/wp-content/uploads/2017/07/CG_WhitePaper_Splunkmon_1216-1.pdf)


### Videos

- [SANS Threat Hunting and IR Summit 2017](https://www.youtube.com/playlist?list=PLfouvuAjspTr95R60Kt7ZcoerR6tYoCLA)
- [SANS Threat Hunting and IR Summit 2016](https://www.youtube.com/playlist?list=PLfouvuAjspTokaa-LdUHqszL-KACkCsKT)
- [BotConf 2016 - 使用 Sysmon 和 Splunk 进行高级事件检测和威胁狩猎](https://www.youtube.com/watch?v=vv_VXntQTpE)
- [BSidesCharm 2017 - 活动目录威胁狩猎](https://www.youtube.com/watch?v=9Uo7V9OUaUw)
- [BSidesAugusta 2017 - 机器学习驱动的网络威胁狩猎](https://www.youtube.com/watch?v=c-c-IQ5pFXw)
- [Toppling the Stack: 威胁狩猎的异常检测](https://www.youtube.com/watch?v=7q7GGg-Ws9s)
- [BSidesPhilly 2017 - 威胁狩猎](https://www.youtube.com/watch?v=bDdsGBCUa8I)
- [Black Hat 2017 -去混淆：科学使用 PowerShell 进行混淆检测](https://www.youtube.com/watch?v=x97ejtv56xw)
- [DefCon 25 - MS 只给了蓝队战术核弹](https://www.youtube.com/watch?v=LUtluTaEAUU)
- [BSides London 2017 - 猎杀与被猎杀](https://www.youtube.com/watch?v=19H7j_sZcKc)
- [SecurityOnion 2017 - 有效抓住坏人](https://www.youtube.com/watch?v=_QVhMPGtIeU)
- [SkyDogCon 2016 - 狩猎：黑魔法防御课](https://www.youtube.com/watch?v=mKxGulV2Z74)
- [BSidesAugusta 2017 - 不要使用 Google 搜索 PowerShell Hunting](https://www.youtube.com/watch?v=1mfVPLPxKTc)
- [BSidesAugusta 2017 - 狩猎对手调查手册与 OpenCNA](https://www.youtube.com/watch?v=8qM-DnmHNv8)
- [关联数据的可视化狩猎](https://www.youtube.com/watch?v=98MrgfTFeMo)
- [RVAs3c - 痛苦金字塔：情报驱动的威胁检测与响应来增加对手的成本](https://www.youtube.com/watch?v=zlAWbdSlhaQ)
- [BSidesLV 2016 - Powershell 终端狩猎](https://www.youtube.com/watch?v=2MrrOxsJk_M)
- [Derbycon 2015 - 入侵狩猎使用指南](https://www.youtube.com/watch?v=MUUseTJp3jM)
- [BSides DC 2016 - 从机器学习入手进行事件检测](https://www.youtube.com/watch?v=2FvP7nwb2UE&feature=youtu.be)
- [SANS Webcast 2018 - 什么是事件日志？第一部分：攻击者删除事件日志的技巧](https://www.youtube.com/watch?v=7JIftAw8wQY)


### Trainings

- [Threat Hunting Academy](https://threathunting.org)
- [SANS FOR508](https://www.sans.org/course/advanced-incident-response-threat-hunting-training) - 高级数字取证、事件响应与威胁狩猎
- [eLearnSecurity THP](https://www.elearnsecurity.com/course/threat_hunting_professional/) - 威胁狩猎专家


### Twitter

- ["Awesome Detection" Twitter List](https://twitter.com/0x4d31/lists/awesome-detection) - 那些讨论威胁检测、狩猎、DFIR 和红队的安全人员
- ["Awesome Detection" Collection](https://twitter.com/0x4d31/timelines/952125848508772353) - 有关威胁检测、狩猎、DFIR 和那些对创建检测逻辑有帮助的红队技术文章的集合
- [Top #infosec Twitter Accounts](https://sqrrl.com/top-infosec-twitter-accounts/) (威胁猎手的视角)


## Contribute

欢迎共享！请先阅读[贡献指南](CONTRIBUTING.md)


## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0)

在法律允许的范围内，Adel &#34;0x4D31&#34; Karimi 不保留所有权利和相关附属权利
