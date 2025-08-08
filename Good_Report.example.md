# Cyber Threat Intelligence Analysis Report

**SBOM File:** `sbom_log4j.json`

## Executive Summary

**Executive Summary**

This report summarizes the findings from a recent vulnerability assessment, identifying a total of **4 vulnerabilities** within our environment. A significant concern is the presence of **2 vulnerabilities** listed in the CISA Known Exploited Vulnerabilities (KEV) catalog, indicating they are actively being exploited by threat actors. Additionally, **2 vulnerabilities** are categorized as high-risk due to their severe potential impact and ease of exploitation.

The existence of actively exploited and high-risk vulnerabilities presents a substantial and immediate threat to our systems and data integrity. Therefore, it is strongly recommended to prioritize remediation efforts immediately. Focus should first be directed towards patching the vulnerabilities identified in the KEV catalog, followed closely by addressing other high-risk vulnerabilities, to swiftly reduce the most critical risks to the organization's security posture.

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

- Update Apache Log4j2 to version 2.15.0 or higher (preferably 2.16.0 or 2.17.1+) to disable JNDI lookup behavior by default and remove vulnerable functionality.
- For Log4j versions 2.10 and later, mitigate by setting the system property `log4j2.formatMsgNoLookups` or the environment variable `LOG4J_FORMAT_MSG_NO_LOOKUPS` to `true`.
- For Log4j versions 2.0-beta9 to 2.10.0, remove the `JndiLookup` class from the classpath (e.g., `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`).
- Update Java Development Kit (JDK) to versions greater than 6u211, 7u201, 8u191, and 11.0.1, as they set `com.sun.jndi.ldap.object.trustURLCodebase` to `false`, preventing remote codebase loading via LDAP.
- Filter inbound network requests that contain the string `${jndi:` to block common exploitation attempts.
- Monitor web application and server logs (e.g., `catalina.out`, `mifs.log`, `websso.log`, `analytics.log`) for evidence of `jndi:ldap` strings and unusual command execution, such as `curl`.
- Apply vendor-specific security patches and hotfixes for all affected products and services (e.g., Cisco, Arista, Siemens, SAS).
- Implement a Web Application Firewall (WAF) with CVE-specific rules to protect against common web-based attack vectors.
- Deploy Runtime Application Self-Protection (RASP) solutions for Java applications to provide last-mile protection against exploitation.
- Configure outbound network filters as default-deny to prevent successful remote callbacks from vulnerable systems.
- Utilize updated vulnerability scanning tools (e.g., Qualys, Rapid7, Tenable) that include signatures for CVE-2021-44228 attack vectors.
- Take systems and services with known-vulnerable implementations offline immediately if patching is not feasible.
- Regularly consult and prioritize updates based on vendor security advisories mentioning Log4j.

**Snort Rules:**

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"SERVER-OTHER Apache Log4j2 JNDI DNS exfiltration attempt"; flow:to_client,established; content:"lookup"; fast_pattern; content:"dns:"; pcre:"/\$\{jndi:(ldap|ldaps|dns|rmi|iiop|http):\/\/[^\}]+\}/i"; http_client_body; http_uri; http_header; reference:cve,2021-44228; classtype:misc-activity; sid:58722; rev:1;)
```

Description: Detects attempts to exfiltrate data via DNS using Apache Log4j2 JNDI lookups.

Source URL: https://snort.org/rules/58722

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"SERVER-OTHER Apache Log4j2 JNDI LDAP exfiltration attempt"; flow:to_client,established; content:"lookup"; fast_pattern; content:"ldap:"; pcre:"/\$\{jndi:(ldap|ldaps|dns|rmi|iiop|http):\/\/[^\}]+\}/i"; http_client_body; http_uri; http_header; reference:cve,2021-44228; classtype:misc-activity; sid:58723; rev:1;)
```

Description: Detects attempts to exfiltrate data via LDAP using Apache Log4j2 JNDI lookups.

Source URL: https://snort.org/rules/58723

```snort
alert tcp $HTTP_PORTS any -> $HOME_NET any (msg:"SERVER-OTHER Apache Log4j2 JNDI reference download attempt"; flow:to_server,established; content:"lookup"; fast_pattern; pcre:"/\$\{jndi:(ldap|ldaps|dns|rmi|iiop|http):\/\/[^\}]+\}/i"; http_uri; http_header; reference:cve,2021-44228; classtype:misc-activity; sid:58730; rev:1;)
```

Description: Detects inbound Apache Log4j2 JNDI lookup attempts in HTTP URI or headers.

Source URL: https://snort.org/rules/58730

**Sigma Rules:**

```yaml
title: Apache Log4j (Log4Shell) JNDI Lookup in Web Logs
logsource:
  category: webserver
  service: access_log
detection:
  selection:
    cs-uri-query|contains|all:
      - '$'
      - '{'
      - 'jndi:'
      - '}'
    cs-uri-query|contains:
      - 'ldap://'
      - 'ldaps://'
      - 'rmi://'
      - 'dns://'
      - 'iiop://'
      - 'http://'
  condition: selection
```

Description: Detects Apache Log4j (Log4Shell) exploitation attempts by looking for JNDI lookup patterns in web access logs.

Source URL: https://github.com/SigmaHQ/sigma/blob/master/rules/web/access_log/web_apache_log4j_cve_2021_44228.yml

```yaml
title: Log4j CVE-2021-44228 PowerShell Download Cradle
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-w hiden'
      - '-noP'
      - '-c IEX((new-object net.webclient).downloadstring'
      - '.downloadfile'
      - '.DownloadString'
    CommandLine|re:
      - '\$\s*\{jndi\:ldap\:\/\/[^\}]+\}\'
  condition: selection
```

Description: Detects PowerShell download cradle activity that might indicate post-exploitation from Log4Shell, often seen after successful initial exploitation.

Source URL: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_log4j_powershell_download_cradle.yml

```yaml
title: Log4j JNDI DNS Lookup in Windows DNS Logs
logsource:
  product: windows
  service: dns-server
detection:
  selection:
    QueryName|contains:
      - '.jndi.'
      - '.ldap.'
      - '.rmi.'
      - '.dns.'
      - '.iiop.'
      - '.http.'
  condition: selection
```

Description: Detects suspicious DNS queries related to Log4j JNDI lookups in Windows DNS server logs, indicating potential exploitation attempts.

Source URL: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_dns_log4j_lookup.yml

**Yara Rules:**

```yara
rule gen_log4j_exploit {
  meta:
    author = "Florian Roth"
    date = "2021-12-10"
    modified = "2021-12-11"
    description = "Detects Log4j JNDI exploitation strings in various forms."
    hash = "5266e74f1b4c3e800d33e1430030508a"
    severity = "critical"
    os = "windows,linux,macos"
    filetype = "text"
    tags = "exploit,log4j,log4shell"
    rule_version = "v1"
  strings:
    $s1 = "${jndi:ldap:"
    $s2 = "${jndi:ldaps:"
    $s3 = "${jndi:rmi:"
    $s4 = "${jndi:dns:"
    $s5 = "${jndi:iiop:"
    $s6 = "${jndi:http:"
    $s7 = "${lower:j}${lower:n}${lower:d}i:"
    $s8 = "${upper:J}${upper:N}${upper:D}I:"
    $s9 = "${::-j}${::-n}${::-d}i:"
    $sa = "${java:version}"
    $sb = "${env:"
    $sc = "${sys:"
    $sd = "%24%7Bjndi:"
    $se = "%2524%257Bjndi:"
    $sf = "\u0024\u007B"
    $sg = "\x24\x7B"

  condition:
    uint16(0) == 0x4f44 and
    ( 2 of ($s*) or 3 of ($s7,$s8,$s9,$sa,$sb,$sc,$sd,$se,$sf,$sg) )
}
```

Description: Detects various forms of Log4j JNDI exploitation strings, including obfuscated and encoded variants, in files or memory.

Source URL: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_log4j_exploit.yar

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

- Could not extract defensive measures from the provided content due to JSON parsing error.

**Snort Rules:** None found.

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

- Upgrade Apache Log4j2 to fixed versions: 2.17.0, 2.12.3, or 2.3.1, which protect against uncontrolled recursion from self-referential lookups.
- Consult and apply vendor-specific security advisories and patches for products that incorporate vulnerable versions of Apache Log4j2.
- Update integrated third-party software components to later, non-vulnerable versions as they become available.
- Protect network access to devices with appropriate mechanisms and configure IT environments according to industrial security guidelines and product manuals.
- Avoid using non-default Pattern Layout configurations with Context Lookups in Log4j2, as these can enable the denial-of-service condition.

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

- Update Apache Log4j2 to versions 2.17.1, 2.12.4, or 2.3.2 to remediate the vulnerability, as these versions fix the issue by limiting JNDI data source names to the java protocol.
- Limit JNDI data source names to the `java` protocol in Log4j2 configurations to prevent exploitation via malicious LDAP data sources.
- Consult official vendor advisories (e.g., Apache, Cisco, Oracle) for affected products and their specific patching or remediation instructions.
- Implement strict input validation to prevent malicious data from being processed by the application, reducing the attack surface for similar vulnerabilities (as suggested by related CWEs like CWE-20 and CWE-74).
- Apply the principle of least privilege, ensuring that applications and services operate with the minimum necessary permissions, thereby limiting the potential impact of successful exploitation.

**Snort Rules:** None found.

**Sigma Rules:**

```yaml
title: Log4j2 RCE via JDBC Appender Configuration Modification (CVE-2021-44832)
id: 59a0f023-e696-419b-b010-85885e78396d
status: stable
description: Detects suspicious modification of Log4j2 configuration file to use JDBC Appender, which can lead to RCE via CVE-2021-44832.
author: Florian Roth (Nextron Systems)
date: 2021/12/29
modified: 2021/12/30
tags:
    - attack.initial_access
    - attack.execution
    - cve.2021.44832
    - vulnerability.log4j
    - detection.emerging_threats
logsource:
    product: windows
    category: file_event
detection:
    selection_log4j_config:
        TargetFilename|endswith:
            - '\log4j2.xml'
            - '\log4j2.json'
            - '\log4j2.properties'
            - '\log4j2.yml'
            - '\log4j2.yaml'
    selection_jdbc_appender:
        - Content: 'JDBCAppender'
        - Content: 'JndiJdbcDatasource'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```

Description: Detects suspicious modification of Log4j2 configuration files on Windows systems to include JDBC Appender, which is a vector for CVE-2021-44832 exploitation.

Source URL: https://github.com/SigmaHQ/sigma/blob/master/rules/application/log4j/win_log4j_jdbc_appender_config_modification.yml

**Yara Rules:** None found.
