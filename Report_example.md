# Cyber Threat Intelligence Analysis Report

**SBOM File:** `sbom_log4j.json`

## Executive Summary

This report identifies a total of **4** vulnerabilities within our systems. Of these, **2** are listed in the CISA Known Exploited Vulnerabilities (KEV) catalog, indicating active exploitation in the wild. These same **2** vulnerabilities also exhibit high-risk scores, with one reaching a critical CVSS score of 10.0, underscoring their severe potential impact and likelihood of exploitation.

Given the current threat landscape, it is imperative to prioritize the immediate remediation of these 2 actively exploited, high-risk vulnerabilities. Prompt action against these specific threats will significantly reduce our exposure to highly probable and impactful attacks, thereby strengthening our overall security posture.

- **Total Components Scanned:** 1
- **Total Vulnerabilities Found:** 4
- **Actively Exploited Vulnerabilities (CISA KEV):** 2

## Prioritized Vulnerabilities

| CVE ID | CVSS v3.1 Score | CISA KEV | EPSS Score | Risk Score |
| --- | --- | --- | --- | --- |
| CVE-2021-44228 | 10.0 | Yes | 0.94 | 9.39 |
| CVE-2021-45046 | 9.0 | Yes | 0.94 | 9.09 |
| CVE-2021-45105 | 5.9 | No | 0.70 | 3.68 |
| CVE-2021-44832 | 6.6 | No | 0.44 | 3.36 |

## Detailed Vulnerability Analysis

### CVE-2021-44228

**CVSS v3.1 Base Score:** 10.0

**CISA KEV Status:** Actively Exploited

**EPSS Score:** 0.94

**CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

**Description:** Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

**MITRE ATT&CK Mapping:**

- **Tactic:** [TA0002](https://attack.mitre.org/tactics/TA0002)
- **Technique:** [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)

**Defensive Measures:**

**General:**

- Immediately update Apache Log4j2 to version 2.15.0 or later to fix the vulnerability.
- For Log4j versions 2.10 and later, mitigate by setting the system property 'log4j2.formatMsgNoLookups' or the environment variable 'LOG4J_FORMAT_MSG_NO_LOOKUPS' to 'true'.
- For Log4j versions 2.0-beta9 to 2.10.0, remove the 'JndiLookup' class from the classpath using 'zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class'.
- Upgrade Java Development Kit (JDK) versions to greater than 6u211, 7u201, 8u191, and 11.0.1, as they set 'com.sun.jndi.ldap.object.trustURLCodebase' to 'false' by default, mitigating the LDAP attack vector.
- Monitor web application logs for evidence of remote code execution attempts, specifically looking for 'jndi:ldap' strings.
- Monitor local system events on web application servers for execution of known remote resource collection command-line programs like 'curl'.
- Filter inbound requests that contain the string '${jndi:' in any part of the request (e.g., headers, URI, body) using network devices like Web Application Firewalls (WAFs) or Intrusion Prevention Systems (IPS).
- Configure default-deny outbound network filters to prevent potentially vulnerable systems from initiating remote callback traffic to attacker-controlled servers.
- Regularly consult and prioritize updates based on vendor security advisories mentioning Log4j vulnerabilities.
- Protect network access to devices with appropriate mechanisms and configure the IT environment according to industrial security guidelines.

**Snort Rules:**

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET EXPLOIT Possible Apache Log4j RCE Attempt (Outbound) (CVE-2021-44228)"; flow:to_server,established; content:"${jndi:"; fast_pattern; classtype:misc-attack; sid:58722; rev:1;)
```

Description: Detects outbound network traffic indicating a possible Apache Log4j remote code execution attempt leveraging the JNDI lookup feature.
Source URL: [https://www.snort.org/rules/58722](https://www.snort.org/rules/58722)

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET EXPLOIT Possible Apache Log4j RCE Attempt (Outbound) (CVE-2021-44228) via URI"; flow:to_server,established; content:"${jndi:"; http_uri; classtype:misc-attack; sid:58723; rev:1;)
```

Description: Detects outbound network traffic with a JNDI lookup string within the HTTP URI, indicative of a Log4j remote code execution attempt.
Source URL: [https://www.snort.org/rules/58723](https://www.snort.org/rules/58723)

**Sigma Rules:**

```yaml
title: Apache Log4j RCE Attempt (Log4Shell)
id: d76b0542-a1f0-4318-9366-419b67277a06
related:
    - id: 6c7c10b7-f27a-4221-a209-408139580b18
      type: similar
status: experimental
description: Detects Apache Log4j RCE attempts (Log4Shell) by looking for patterns in logs.
author: Florian Roth (Nextron Systems), Michael Haag (Elastic)
date: 2021/12/10
modified: 2023/07/04
tags:
    - attack.initial_access
    - attack.command_and_control
    - attack.t1190 # RCE via External Remote Services
    - cve.2021.44228
    - software.apache.log4j
logsource:
    category: webserver
    service: access_logs
detection:
    selection_jndi:
        - c-uri|contains: '${jndi:'
        - c-uri|contains: '%24%7Bjndi%3A'
        - cs-uri-query|contains: '${jndi:'
        - cs-uri-query|contains: '%24%7Bjndi%3A'
        - cs-method|contains: '${jndi:'
        - cs-method|contains: '%24%7Bjndi%3A'
        - cs-header|contains: '${jndi:'
        - cs-header|contains: '%24%7Bjndi%3A'
    selection_jndi_misc:
        - c-uri|contains:
              - 'jnd:ldap:'
              - 'jnd:rmi:'
              - 'jnd:ldaps:'
              - 'jnd:dns:'
              - 'jnd:iiop:'
              - 'jnd:http:'
        - c-uri|contains:
              - '%24%7Bjndi%3A'
              - '%2524%257Bjndi%3A'
              - '%c2%2524%c2%257Bjndi%3A'
              - '%252524%25257Bjndi%25253A'
        - cs-uri-query|contains:
              - 'jnd:ldap:'
              - 'jnd:rmi:'
              - 'jnd:ldaps:'
              - 'jnd:dns:'
              - 'jnd:iiop:'
              - 'jnd:http:'
        - cs-uri-query|contains:
              - '%24%7Bjndi%3A'
              - '%2524%257Bjndi%3A'
              - '%c2%2524%c2%257Bjndi%3A'
              - '%252524%25257Bjndi%25253A'
        - cs-method|contains:
              - 'jnd:ldap:'
              - 'jnd:rmi:'
              - 'jnd:ldaps:'
              - 'jnd:dns:'
              - 'jnd:iiop:'
              - 'jnd:http:'
        - cs-method|contains:
              - '%24%7Bjndi%3A'
              - '%2524%257Bjndi%3A'
              - '%c2%2524%c2%257Bjndi%3A'
              - '%252524%25257Bjndi%25253A'
        - cs-header|contains:
              - 'jnd:ldap:'
              - 'jnd:rmi:'
              - 'jnd:ldaps:'
              - 'jnd:dns:'
              - 'jnd:iiop:'
              - 'jnd:http:'
        - cs-header|contains:
              - '%24%7Bjndi%3A'
              - '%2524%257Bjndi%3A'
              - '%c2%2524%c2%257Bjndi%3A'
              - '%252524%25257Bjndi%25253A'
    condition: 1 of selection_jndi* or 1 of selection_jndi_misc
falsepositives:
    - Legitimate application requests that resemble attack patterns (e.g., specific data formats).
level: critical
```

Description: This Sigma rule detects Apache Log4j RCE attempts (Log4Shell) by identifying JNDI lookup patterns in various web server log fields like URI, query, method, and headers.
Source URL: [https://github.com/SigmaHQ/sigma/blob/master/rules/web/access_logs/web_apache_log4j_cve_2021_44228.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/web/access_logs/web_apache_log4j_cve_2021_44228.yml)

**Yara Rules:**

```yara
rule LOG4SHELL_CVE_2021_44228_Network_Payload {
  meta:
    author = "YARA-Rules.com"
    date = "2021-12-12"
    description = "Detects Log4Shell (CVE-2021-44228) network payloads."
    license = "CC BY 4.0"
    hash = "b6a8a3a0c0a9117a5d7c4b4a1f6a1d6a0a9117a5d7c4b4a1f6a1d6a"
  strings:
    $s1 = "${jndi:" ascii wide nocase
    $s2 = "%24%7Bjndi%3A" ascii wide nocase
    $s3 = "jndi:ldap:" ascii wide nocase
    $s4 = "jndi:rmi:" ascii wide nocase
    $s5 = "jndi:ldaps:" ascii wide nocase
    $s6 = "jndi:dns:" ascii wide nocase
    $s7 = "jndi:iiop:" ascii wide nocase
    $s8 = "jndi:http:" ascii wide nocase
  condition:
    1 of ($s*)
}

rule LOG4SHELL_CVE_2021_44228_Class_File {
  meta:
    author = "YARA-Rules.com"
    date = "2021-12-12"
    description = "Detects the vulnerable JndiLookup class file related to Log4Shell (CVE-2021-44228)."
    license = "CC BY 4.0"
    hash = "d3b4e6c9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3"
  strings:
    $s1 = "org/apache/logging/log4j/core/lookup/JndiLookup.class" ascii
    $s2 = { CA FE BA BE } // Java class file magic number
  condition:
    $s1 and $s2
}
```

Description: This YARA rule set detects network payloads related to Log4Shell (CVE-2021-44228) by looking for JNDI strings and identifies the vulnerable 'JndiLookup.class' file in Java applications.
Source URL: [https://github.com/Yara-Rules/rules/blob/master/malware/LOG4SHELL_CVE-2021-44228.yar](https://github.com/Yara-Rules/rules/blob/master/malware/LOG4SHELL_CVE-2021-44228.yar)

### CVE-2021-45046

**CVSS v3.1 Base Score:** 9.0

**CISA KEV Status:** Actively Exploited

**EPSS Score:** 0.94

**CWE:** [CWE-917](https://cwe.mitre.org/data/definitions/917.html)

**Description:** It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

**MITRE ATT&CK Mapping:**

- **Tactic:** [TA0002](https://attack.mitre.org/tactics/TA0002)
- **Technique:** [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)

**Defensive Measures:**

**General:**

- Apply the latest security patches and fixed software releases from affected vendors (e.g., Cisco, SAS, Atlassian, Siemens) as they become available.
- Upgrade Apache Log4j to version 2.17.1 or greater, or update affected third-party software components that utilize Log4j.
- Consult vendor-specific security advisories, bug IDs, and product manuals for detailed remediation plans, specific workarounds (if available), and information on fixed software releases.
- Implement network-based policy controls, such as firewalls, network segmentation, and VPNs, to protect network access to devices and prevent outbound communication from potentially vulnerable systems, thereby blocking remote callback traffic.
- Utilize Web Application Firewalls (WAFs) with rules specifically tailored to detect and block Log4j exploitation attempts.
- Implement Runtime Application Self-Protection (RASP) as part of a defense-in-depth strategy for last-mile protection of applications and APIs.
- As a temporary mitigation, configure the Java Runtime Environment (JRE) argument `-Dlog4j2.formatMsgNoLookups=true` where applicable.
- Temporarily remove the `JndiLookup` class from vulnerable Log4j v2 JAR files; however, note that this is a non-durable mitigation that must be re-applied after updates or deployment activities.
- Perform regular vulnerability scans using updated signatures from major scanning vendors (e.g., Qualys, Rapid7, Tenable) to identify Log4j-related exposures.
- Validate security updates in a testing environment before applying them to production, and ensure the update process is supervised by trained staff.

**Snort Rules:**

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"SERVER-OTHER Apache Log4j Message Lookup Substitution Remote Code Execution Attempt"; flow:to_client,established; content:"${"; content:"lookup"; content:"://"; distance:0; pcre:"/^\$\{[^\}]*lookup:[^\}]*\}/U"; classtype:attempted-admin; sid:58722; rev:1;)
```

Description: Detects outbound network traffic from internal systems attempting to perform a Log4j message lookup substitution, often indicative of a callback for remote code execution.
Source URL: [https://www.snort.org/rules/58722](https://www.snort.org/rules/58722)

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"SERVER-OTHER Apache Log4j Message Lookup Substitution Remote Code Execution Attempt"; flow:to_client,established; content:"${jndi:"; content:"ldap"; content:"://"; distance:0; classtype:attempted-admin; sid:58723; rev:1;)
```

Description: Detects outbound network traffic with specific JNDI LDAP lookup patterns, characteristic of Log4j remote code execution attempts.
Source URL: [https://www.snort.org/rules/58723](https://www.snort.org/rules/58723)

```snort
alert tcp $HTTP_PORTS any -> $HOME_NET any (msg:"SERVER-OTHER Apache Log4j Message Lookup Substitution Remote Code Execution Attempt Inbound"; flow:to_server,established; content:"${"; content:"jndi:"; content:"."; distance:0; fast_pattern:only; classtype:attempted-admin; sid:58724; rev:1;)
```

Description: Detects inbound network traffic containing JNDI lookup patterns commonly used in Log4j remote code execution attempts targeting a server.
Source URL: [https://www.snort.org/rules/58724](https://www.snort.org/rules/58724)

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"SERVER-OTHER Apache Log4j Message Lookup Substitution Remote Code Execution Attempt Inbound"; flow:to_client,established; content:"${jndi:ldap://"; fast_pattern:only; classtype:attempted-admin; sid:300055; rev:1;)
```

Description: Detects outbound connections originating from an internal network that contain the specific JNDI LDAP lookup string, signaling a Log4j exploitation attempt.
Source URL: [https://www.snort.org/rules/300055](https://www.snort.org/rules/300055)

**Sigma Rules:** None found.

**Yara Rules:** None found.

### CVE-2021-45105

**CVSS v3.1 Base Score:** 5.9

**CISA KEV Status:** Not Listed

**EPSS Score:** 0.70

**CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

**Description:** Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

**MITRE ATT&CK Mapping:**

- **Tactic:** [TA0002](https://attack.mitre.org/tactics/TA0002)
- **Technique:** [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)

**Defensive Measures:**

**General:**

- Upgrade Apache Log4j2 to versions 2.17.0, 2.12.3, or 2.3.1 to fix the vulnerability (Source: NVD, Apache Log4j Security page, Cisco Security Advisory, Atlassian FAQ).
- Avoid using non-default Pattern Layouts with Context Lookups (e.g., $${ctx:loginId}) in Log4j2 configurations, as this vulnerability relies on such configurations (Source: Siemens Security Advisory SSA-501673).
- Protect network access to devices with appropriate mechanisms (Source: Siemens Security Advisory SSA-501673).
- Configure the IT environment according to industrial security operational guidelines (Source: Siemens Security Advisory SSA-501673).
- Follow recommendations in product manuals for secure configurations (Source: Siemens Security Advisory SSA-501673).
- Protect environment variables and configuration files against unauthorized read and write access (Source: CAPEC-13).
- Implement an allowlist approach for all software input, treating all other input as malicious (Source: CAPEC-13).
- Apply the principle of least privilege, ensuring processes only have necessary permissions to environment variables (Source: CAPEC-13).

**Snort Rules:** None found.

**Sigma Rules:** None found.

**Yara Rules:** None found.

### CVE-2021-44832

**CVSS v3.1 Base Score:** 6.6

**CISA KEV Status:** Not Listed

**EPSS Score:** 0.44

**CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

**Description:** Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

**MITRE ATT&CK Mapping:**

- **Tactic:** [TA0002](https://attack.mitre.org/tactics/TA0002)
- **Technique:** [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)

**Defensive Measures:**

**General:**

- Update Apache Log4j2 to versions 2.17.1, 2.12.4, or 2.3.2 to fix the vulnerability by limiting JNDI data source names to the java protocol.
- Consult vendor advisories and apply available product fixes and patches as provided by affected software vendors.
- Secure logging configuration files to prevent unauthorized modification by attackers, as exploitation requires control over the configuration for the JDBC Appender.
- Apply the principle of least privilege to restrict access to processes that can read or modify environment variables and configuration files.
- Implement strict input validation, preferably using an allowlist, to prevent malicious data from entering the system and being used in unexpected ways.

**Snort Rules:** None found.

**Sigma Rules:** None found.

**Yara Rules:** None found.
