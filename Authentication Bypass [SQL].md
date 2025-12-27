**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/small-crm-php/)
- Affected Version: [<= v4.0]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Authentication Bypass SQL Injection
- Affected URL: http://127.0.0.1/crm/admin/
- Vulnerable Parameter:  Login page (Username and Password)- Authentication bypass - able to login without valid credentials

**Vulnerable Files:**

- File Name: /admin/
- Path: /admin/index.php

**Vulnerability Type**

- SQL Injection Vulnerability (CWE-89: Authentication Bypass)
- Severity Level: CRITICAL (CVSS: 9.1)

**Root Cause:**
A critical SQL injection vulnerability exists in the login functionality of Small Customer Relationship Management (CRM) allowing authentication bypass. The code directly concatenates user input into SQL query strings without any parameterisation or input validation, allowing attackers to inject malicious SQL code. **_Line 7 is causing the vulnerability_**

crm/admin/index.php
   ❯❯❱ php.lang.security.injection.tainted-sql-string.tainted-sql-string
          User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL
          strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL
          strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate
          data from the database. Instead, use prepared statements (`$mysqli->prepare("INSERT INTO test(id,
          label) VALUES (?, ?)");`) or a safe library.

            7┆ $ret=mysqli_query($con,"SELECT * FROM admin WHERE name='".$_POST['email']."' and
               password='".$_POST['password']."'");  

**Impact:**

- Bypass authentication completely
- Access any user account without credentials
- Gain administrative access

**Description:**
-------------------------------------------------------------------------------------------------------------------------------------

**1. Vulnerability Details:**
The login functionality in [specific file, e.g., /crm/admin] does not  properly sanitize user input before using it in SQL queries. This  allows an attacker to inject malicious SQL code through the username parameter.

**Vulnerable Code Example**
<img width="1108" height="337" alt="Screenshot 2025-12-27 at 14 29 51" src="https://github.com/user-attachments/assets/aca20376-0cdf-46a9-a6bf-293880a4405e" />


**Step-by-Step Reproduction**
1. Navigate to the login page: http://127.0.0.1/crm/admin/ 
2. In the username field, enter: 1 'or' 1=1--
3. In the password field, enter any value or paste the same payload 1 'or' 1=1--
4. Click the login button
5. Observe successful authentication bypass

**Screenshots**
[Attach screenshots showing:]
- Login page with injected payload
- Successful bypass (dashboard/admin panel access)

<img width="1035" height="595" alt="Screenshot 2025-12-27 at 14 05 33" src="https://github.com/user-attachments/assets/7f87b6cf-c27b-4ef5-b4e6-faab875052c0" />


<img width="1504" height="859" alt="Screenshot 2025-12-27 at 14 05 19" src="https://github.com/user-attachments/assets/2f123fcc-acd0-4140-9aff-d12f46b1c3c9" />


**Impact Assessment**
An attacker can:
- Bypass authentication completely
- Access any user account without credentials
- Gain administrative access
- Access sensitive data in the database
- Potentially modify or delete data
- Launch further attacks on the system

**Affected Components**
- User authentication system
- Admin authentication system
- Any other login forms in the application

**Remediation Recommendations**
**Immediate Fix**
1. Use prepared statements (parameterized queries)
2. Implement input validation
3. Apply principle of least privilege for database accounts

**Secure Code Example**
```php
// Use PDO with prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
$user = $stmt->fetch();

**References**

- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection 
- CWE-89: https://cwe.mitre.org/data/definitions/89.html 
- Implement logging and monitoring mechanisms
