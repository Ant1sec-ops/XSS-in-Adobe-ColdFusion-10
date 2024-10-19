# XSS-in-Adobe-ColdFusion-10
Reflected Cross Site Scripting in Adobe ColdFusion 10 in emailadd field.
---

# Adobe ColdFusion 10 - Cross-Site Scripting (XSS) Vulnerability

### Description

This repository documents a **Cross-Site Scripting (XSS) vulnerability** discovered in **Adobe ColdFusion 10**, specifically affecting the `forgot_password.cfm` functionality.

- **Vulnerable URL:** `https://www.example.net/login/forgot_password.cfm`
- **Vulnerable Parameter:** `emailadd`

### Issue Summary

**Cross-Site Scripting (XSS)** is a client-side code injection attack where an attacker can execute malicious scripts in the context of a trusted website. XSS occurs when a web application improperly handles user input, which is then incorporated into the output without proper validation or encoding. This allows attackers to execute arbitrary JavaScript in the victim's browser.

### Exploit Details

The vulnerability was identified in the **POST** parameter `emailadd`, which was found to be vulnerable to URL-encoded XSS payloads. Example of the injected payload:

```plaintext
sample@email.tst'"()&%<acx><ScRiPt >QwBJ(9461)</ScRiPt>
```

When this payload is processed without proper sanitization, the following security risks arise:

- **Session Hijacking**: Malicious scripts can gain access to sensitive information like cookies, often containing session tokens, allowing an attacker to impersonate legitimate users.
- **Arbitrary Page Modifications**: JavaScript can modify the contents of the displayed page, misleading users or performing unauthorized actions on their behalf.

### Impact

This vulnerability opens the door to numerous attack scenarios, including:

- **Session Hijacking**: By stealing session tokens from cookies, attackers can impersonate legitimate users.
- **Social Engineering Attacks**: XSS can be combined with social engineering tactics to further exploit users by displaying fake login forms or malicious content.
- **Content Manipulation**: Attackers can manipulate how the page is presented to users, leading to phishing or other malicious actions.

### Solution

To prevent **XSS** vulnerabilities, it's critical to adopt **secure input handling** techniques. The two key approaches to mitigating XSS risks are:

1. **Input Encoding**:
   - Ensure that user input is **encoded** before being included in the web page, so it is treated as data rather than executable code.

2. **Input Validation**:
   - Validate user input to ensure that it only contains allowed characters or values. Malicious code should be filtered out at the earliest possible stage.

Both **encoding** and **validation** are essential tools for preventing XSS, and the method used should depend on the context of the vulnerable input field.

### References

- [CVE Report](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-27766)
- [XSS Prevention Guide by OWASP](https://owasp.org/www-community/attacks/xss/)
- [ColdFusion Security Guidelines](https://helpx.adobe.com/coldfusion/security.html)

---

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
