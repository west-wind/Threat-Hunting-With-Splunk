# Threat Hunting with Splunk
Awesome Splunk SPL queries that can be used to detect the latest vulnerability exploitation attempts &, threat hunt for MITRE ATT&CK TTPs. I'm including queries with regular expressions, so detection will be possible even if you haven't parsed the logs properly. 

## MITRE ATT&CK TTP & Detection Analytics

| TTP | MITRE ATT&CK | Detection SPL |
|----------|:-------------:|------:|
| T1053.003 |  [Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/) | [T1053.003 Detection SPL](https://github.com/west-wind/Threat-Hunting-With-Splunk/blob/main/MITRE/T1053.003.spl) |
| T1190 |  [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | [T1190 Detection SPL](https://github.com/west-wind/Threat-Hunting-With-Splunk/blob/main/MITRE/T1190.spl) |


## Vulnerabilities & Detection Analytics

| Vulnerability | Advisory | Detection SPL |
|----------|:-------------:|------:|
| CVE-2022-42889 |  [CVE-2022-42889 Advisory](https://nvd.nist.gov/vuln/detail/CVE-2022-42889) | [Text4Shell Detection SPL](https://github.com/west-wind/CVE-2022-42889#detection-splunk-query) |
| CVE-2022-41082 |  [CVE-2022-41082 Advisory](https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/) | [Microsoft Exchange 0day Detection SPL](https://github.com/west-wind/Threat-Hunting-With-Splunk/blob/main/CVE/CVE-2022-41082) |
| CVE-2022-22954 |  [CVE-2022-22954 Advisory](https://github.com/advisories/GHSA-q7xc-35g4-g566) | [CVE-2022-22954 Detection SPL](https://github.com/west-wind/Threat-Hunting-With-Splunk/blob/main/CVE/CVE-2022-22954) |
| CVE-2022-22965 |  [CVE-2022-22965 Advisory](https://github.com/advisories/GHSA-36p3-wjmg-h94x) | [CVE-2022-22965 Detection SPL](https://github.com/west-wind/Spring4Shell-Detection) |
| CVE-2022-22963 |  [CVE-2022-22963 Advisory](https://nvd.nist.gov/vuln/detail/CVE-2022-22963) | [CVE-2022-22963 Detection SPL](https://github.com/west-wind/Spring4Shell-Detection/blob/main/README.md#detection-for-cve-2022-22963-not-spring4shell) |
| CVE-2022-2185 |  [CVE-2022-2185 Advisory](https://nvd.nist.gov/vuln/detail/CVE-2022-2185) | [GitLab Malicious Project Upload Detection SPL](https://github.com/west-wind/Threat-Hunting-With-Splunk/blob/main/CVE/CVE-2022-2185) |
| CVE-2022-33891 |  [CVE-2022-33891 Advisory](https://nvd.nist.gov/vuln/detail/CVE-2022-33891) | [Apache Spark Command Injection Detection SPL](https://github.com/west-wind/CVE-2022-33891) |

## Malware Detection Analytics

| Malware | Reference | Detection SPL |
|----------|:-------------:|------:|
| BPFDoor |  [BPFDoor ATT&CK Community Presentation](https://github.com/CiscoCXSecurity/presentations/blob/master/Auditd%20for%20the%20newly%20threatened.pdf) | [BPFDoor Detection SPL](https://github.com/west-wind/Threat-Hunting-With-Splunk/blob/main/Malware-Backdoors/BPFDoor) |
| VIRTUALPITA & VIRTUALPIE |  [Mandiant Report - Investigating Novel Malware Persistence Within ESXi Hypervisors](https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence) | [Detection SPL](https://github.com/west-wind/Threat-Hunting-With-Splunk/blob/main/Malware-Backdoors/VirtualPITA%20&%20VirtualPIE) |
| Linux Ransomware/Wiper |  [Linux Ransomware Report from UPTYCS](https://www.uptycs.com/blog/another-ransomware-for-linux-likely-in-development) | [Ransomware Detection SPL](https://github.com/west-wind/Threat-Hunting-With-Splunk/blob/main/Malware-Backdoors/Linux%20Ransomware) |

