**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/small-crm-php/)
- Affected Version: [<= v4.0]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Broken Access Control / Missing Authorization
- Affected URL: http://127.0.0.1/crm/
- Vulnerable Parameter:  /crm/admin/*.php - Authorization Module

**Vulnerable Files:**

- File Name: /admin/
- Path: /crm/admin/, /crm/login.php

**Vulnerability Type**

- Broken Access Control / Missing Authorization CWE: CWE-284, CWE-862, CWE-639
- Severity Level: CRITICAL (CVSS: 9.9)

**Root Cause:**
The application lacks authorization checks on administrative functions, only verifying that users are authenticated without validating their role or permissions. This allows any logged-in user to access admin pages by directly navigating to admin URLs.
_**Missing Role in Session - Lines 9-11**_
$_SESSION['login']=$_POST['email'];
$_SESSION['id']=$num['id'];
$_SESSION['name']=$num['name'];

_**// MISSING: $_SESSION['role']=$num['role'];**_

**Impact:**

- An authenticated attacker with low-level user privileges can gain complete administrative access to the application, view and modify all user data, escalate privileges, and compromise the entire system.

**Vulnerability Details:**
-------------------------------------------------------------------------------------------------------------------------------------

**Description:**
A critical vulnerability has been found in small CRM Application where the authorization mechanism fails to verify user roles before serving 
administrative content. The application only checks if a user is authenticated but does not verify their authorization level. Any authenticated user can access administrative functions by directly navigating to admin URLs (e.g., /crm/admin/home.php, /crm/admin/edit-user.php) without any role verification. This allows complete privilege escalation from regular user to administrator, enabling unauthorized access to sensitive data, user modification, and system compromise.

**Vulnerable Code Example:**

<img width="516" height="75" alt="Screenshot 2025-12-30 at 23 00 27" src="https://github.com/user-attachments/assets/1f9146a8-7de6-4910-ac6c-9ec79363f3e7" />

**Step-by-Step Reproduction**
**Attack Scenario**

First Scenario: 
- Attacker logs in with regular user credentials
- Attacker modifies url path to access admin URLs (e.g., /crm/admin/home.php, /admin/edit-user.php)
- Application serves admin content without checking user role
- Attacker gains full administrative capabilities

Second Scenario:
- Attacker logs in with regular user credentials
- Intercept the request in Burpsuite
- Modify the request "_GET /crm/dashboard.php HTTP/1.1_" to "_/crm/admin/home.php, /admin/edit-user.php_"
- And Observe the response that application serves admin content without checking user role

**Screenshots**
[Attach screenshots showing:]
- Login as regular user credentials
- Modifies url path to access admin URLs (e.g., /crm/admin/home.php, /admin/edit-user.php) (dashboard/admin panel access)

<img width="1626" height="804" alt="Screenshot 2025-12-30 at 21 49 23" src="https://github.com/user-attachments/assets/0d5de6a3-9477-4897-b9b9-3c23b525ff29" />


<img width="1935" height="789" alt="Screenshot 2025-12-30 at 22 29 21" src="https://github.com/user-attachments/assets/ea595934-4d84-417c-bb49-2febfec31105" />

<img width="1993" height="701" alt="Screenshot 2025-12-30 at 21 50 06" src="https://github.com/user-attachments/assets/3846d291-2cd3-467c-aafa-308edb10a0d2" />


**_Second Scenario:_**

<img width="1735" height="967" alt="Screenshot 2025-12-30 at 21 42 51" src="https://github.com/user-attachments/assets/bc6c7858-d495-424a-9cf4-1bceabd029ad" />

<img width="1701" height="1066" alt="Screenshot 2025-12-30 at 21 45 57" src="https://github.com/user-attachments/assets/1fb1f520-e135-45f6-a635-ee7767e63712" />


**Impact Assessment**
The absence of role-based access control allows any authenticated user to:
- Access all administrative functions
- Bypass all authorization boundaries
- Escalate privileges without any challenge
- Perform actions reserved for administrators

**Affected Components**
- User authentication system
- Admin authentication system
- User deletion functionality

**Remediation Recommendations**
**Immediate Fix**
1. Implement role-based access control (RBAC)
2. Store user roles in session during authentication
3. Verify roles before serving any privileged content
4. Use a centralized authorization function
5. Apply principle of least privilege
6. Conduct security code review

**Secure Code Example**
```php
if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die('Access Denied');
}

OR

<?php
// /crm/admin/edit-user.php - SECURE VERSION
session_start();

// Step 1: Check authentication (logged in?)
if(!isset($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit();
}

// Step 2: Check authorization (is admin?) - CRITICAL FIX!
if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    // Log the unauthorized attempt
    error_log(sprintf(
        "[%s] Unauthorized access attempt to %s by user %s (role: %s) from IP %s",
        date('Y-m-d H:i:s'),
        $_SERVER['REQUEST_URI'],
        $_SESSION['username'] ?? 'unknown',
        $_SESSION['role'] ?? 'none',
        $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ));
    
    // Deny access
    http_response_code(403);
    die('Access Denied: Administrator privileges required');
}

// Now safe to proceed - user is authenticated AND authorized
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if($user_id === false) {
    die('Invalid user ID');
}

// ... process edit user ...
?>

**References**

- OWASP Broken Access Control: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/ 
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
