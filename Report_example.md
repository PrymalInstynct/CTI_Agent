# Cyber Threat Intelligence Analysis Report

**SBOM File:** `sbom_log4j.json`

## Executive Summary

- **Total Components Scanned:** 1
- **Total Vulnerabilities Found:** 4
- **Actively Exploited Vulnerabilities (CISA KEV):** 1

## Prioritized Vulnerabilities

| CVE ID | CVSS v3.1 Score | CISA KEV | Risk Score |
| --- | --- | --- | --- |
| CVE-2021-44228 | 10.0 | Yes | 9.00 |
| CVE-2021-45046 | 9.0 | No | 4.60 |
| CVE-2021-44832 | 6.6 | No | 3.64 |
| CVE-2021-45105 | 5.9 | No | 3.36 |


## Detailed Vulnerability Analysis

### CVE-2021-44228

**CVSS v3.1 Base Score:** 10.0

**CISA KEV Status:** Actively Exploited

**CWE:** CWE-20

**Description:** Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

**MITRE ATT&CK Mapping:**

- **Tactic:** TA0002
- **Technique:** T1059: Command and Scripting Interpreter

**Defensive Measures:**

**SIGMA Rules:**

```yaml
title: Suspicious Process Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName: '*\powershell.exe'
  condition: selection
```

### CVE-2021-45046

**CVSS v3.1 Base Score:** 9.0

**CISA KEV Status:** Not Listed

**CWE:** CWE-917

**Description:** It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

**MITRE ATT&CK Mapping:**

- **Tactic:** TA0002
- **Technique:** T1059: Command and Scripting Interpreter

**Defensive Measures:**

**SIGMA Rules:**

```yaml
title: Suspicious Process Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName: '*\powershell.exe'
  condition: selection
```

### CVE-2021-44832

**CVSS v3.1 Base Score:** 6.6

**CISA KEV Status:** Not Listed

**CWE:** CWE-20

**Description:** Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

**MITRE ATT&CK Mapping:**

- **Tactic:** TA0002
- **Technique:** T1059: Command and Scripting Interpreter

**Defensive Measures:**

**SIGMA Rules:**

```yaml
title: Suspicious Process Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName: '*\powershell.exe'
  condition: selection
```

### CVE-2021-45105

**CVSS v3.1 Base Score:** 5.9

**CISA KEV Status:** Not Listed

**CWE:** CWE-20

**Description:** Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

**MITRE ATT&CK Mapping:**

- **Tactic:** TA0002
- **Technique:** T1059: Command and Scripting Interpreter

**Defensive Measures:**

**SIGMA Rules:**

```yaml
title: Suspicious Process Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName: '*\powershell.exe'
  condition: selection
```
