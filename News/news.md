# Industrial cybersecurity news

---
## [VULNERABILITES] Mitsubishi Controllers MELSEC iQ-R

_12/06/2020_
```
This vulnerability impacts the MELSEC iQ-R CPU modules from Mitsubishi.
 The DOS attack impacts the operation of the PLC. Mitsubishi has released a patch.
```

> ###### CVE :
> [CVE-2020-13238](https://nvd.nist.gov/vuln/detail/CVE-2020-13238)
> ###### Sources :
- [EN] [CERT-US](https://www.us-cert.gov/ics/advisories/icsa-20-161-02)
- [EN] [SecurityWeeks](https://www.securityweek.com/vulnerability-mitsubishi-controllers-can-allow-hackers-disrupt-production)


---
## [ATTACK] [RANSOMWARE] EKANS/SNAKE at Honda and Enel
_10/06/2020_

```
The EKANS/SNAKE ransom paralyses 11 Honda factories (5 in the USA, 2 in Brazil, India and Turkey).
This ransomware has features that target industrial systems.
In the case of Honda or Enel group, the RDP track open on the Internet is privileged. 
```
Publication FR : [EKANS ransomware PDF](https://github.com/CyberSecICS/CyberSecICS.github.io/blob/master/Publications/2020_04_04_EKANS_RANSOMWARE.pdf)

> ###### IOC EKANS/SNALE
>
>General :
- MAIL : `bapcocrypt@ctemplar.com`
- SHA-256 : `e5262db186c97bbe533f0a674b08ecdafa3798ea7bc17c705df526419c168b60`
>
>File at Honda :
- SHA2-256 : `d4da69e424241c291c173c8b3756639c654432706e7def5025a649730868c4a1`
- NDD      : `mds.honda.com`
>
>File at Enel :
- SHA2-256 : `edef8b955468236c6323e9019abb10c324c27b4f5667bc3f85f3a097b2e5159a`
- NDD      : `enelint.global`
>
> ###### Règles YARA :
> On [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/yara/win.snake)
>
> ###### MITRE ATT&CK TIDs :
On [VMware carbonblack](https://www.carbonblack.com/2020/01/27/threat-analysis-unit-tau-threat-intelligence-notification-snake-ransomware/)
>
> ###### _Sources_ :
  - [FR] [Pressecitron](https://www.presse-citron.net/honda-essaie-de-gerer-les-consequences-dune-cyberattaque-denvergure/)
  - [EN] [Bleepingcomputer](https://www.bleepingcomputer.com/news/security/honda-investigates-possible-ransomware-attack-networks-impacted/)
  - [EN] [Forbes](https://www.forbes.com/sites/daveywinder/2020/06/10/honda-hacked-japanese-car-giant-confirms-cyber-attack-on-global-operations-snake-ransomware/)
  - [EN] [Medium - Malware analysis](https://medium.com/@nishanmaharjan17/malware-analysis-snake-ransomware-a0e66f487017)
  - [EN] [Dragos](https://www.dragos.com/blog/industry-news/ekans-ransomware-and-ics-operations/)

---
## [VULNERABILITES] Schneider Electric Easergy

_10/06/2020_
```
 Multiple vulnerabilities on Schneider Electric Easergy T300 products earlier than 2.7 and Easergy Builder products earlier than 1.6.3.0.
 Risks :
  - Remote execution of arbitrary code
  - Remote denial of service
  - Data Integrity Breaches
  - Breach of confidentiality of data
  - Elevation of privileges
  - Injection of illegitimate rebound requests (SRFC)
```

> ###### CVE :
> CVE-2020-7503 à CVE-2020-7519
> ###### Sources :
- [FR] [CERTFR-2020-AVI-357](https://www.cert.ssi.gouv.fr/avis/CERTFR-2020-AVI-357/)
- [EN] [Schneider Electric 1](https://download.schneider-electric.com/files?p_enDocType=Technical+leaflet&p_File_Name=SEVD-2020-161-04_Easergy_T300_Security_Notification.pdf&p_Doc_Ref=SEVD-2020-161-04)
- [EN] [Schneider Electric 2](https://download.schneider-electric.com/files?p_enDocType=Technical+leaflet&p_File_Name=SEVD-2020-161-05_Easergy_Builder_Security_Notification.pdf&p_Doc_Ref=SEVD-2020-161-05)


---

## [VULNERABILITES] Siemens
_09/10/2020_

```
Multiples Siemens dans les SIMATIC, SINEMA, SINUMERIK, SINUMERIK et LOGO! 8 BM.
- Remote execution of arbitrary code
- Denial of Service
- Circumvention of security policy
- Data Integrity Breaches
- Breach of confidentiality of data
```

> ###### CVE :
- CVE-2020-7580
- CVE-2020-7585 and CVE-2020-7586
- CVE-2020-7589
- CVE-2018-15361
- CVE-2019-8258 to CVE-2019-8277
- CVE-2019-8280
>    
> ###### Sources :
- [FR] [CERTFR-2020-AVI-349](https://www.cert.ssi.gouv.fr/avis/CERTFR-2020-AVI-349/)
- [EN] [Siemens 1](https://cert-portal.siemens.com/productcert/pdf/ssa-689942.pdf)   
- [EN] [Siemens 2](https://cert-portal.siemens.com/productcert/pdf/ssa-312271.pdf)  
- [EN] [Siemens 3](https://cert-portal.siemens.com/productcert/pdf/ssa-927095.pdf)  
- [EN] [Siemens 4](https://cert-portal.siemens.com/productcert/pdf/ssa-312271.pdf)  
- [EN] [SecurityWeek](https://www.securityweek.com/critical-vulnerabilities-expose-siemens-logo-controllers-attacks)
