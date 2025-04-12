# 🛡️ Activity Logger & Security Monitor

A custom WordPress plugin developed to monitor employee activities and enhance security on WordPress websites. It logs critical actions, detects suspicious behaviors, and sends real-time email alerts for security anomalies.

---

## 🔍 Key Features

- ✅ Tracks and logs all employee/user activities
- ✅ Detects suspicious behavior and file changes
- ✅ Sends real-time email alerts for critical security events
- ✅ Provides admin dashboard with categorized logs
- ✅ Exportable logs in CSV format

---

## 📊 Logs Captured

| Event | Description |
|-------|-------------|
| User Login Attempts | Successful and failed logins |
| Admin User Changes | New admin users created |
| Plugin & Theme Changes | Activation, deletion, updates |
| File Changes | Creation, deletion, modifications |
| Access Attempts | wp-config.php, .htaccess, etc. |
| IP Access Logs | Unusual IP or first-time access |
| DB Modifications | Unauthorized database changes |
| New Plugins | Detected unauthorized installs |
| SSL/Permission Changes | Firewall disabled, SSL off, etc. |
| File Permission Edits | For `/wp-content/`, `/admin/` etc. |
| Malicious Pattern Detection | XSS, XML-RPC abuse, outdated plugins/themes |
| Suspicious API Calls | Unknown third-party endpoints |
| Backup Modifications | Creation or changes in backups |
| Failed Security Checks | Triggered scan errors or failures |

---

## 📬 Email Alert Example

Here’s how real-time email alerts look when suspicious activity is detected:

![Screenshot 2025-04-12 135256](https://github.com/user-attachments/assets/93e38dee-dd36-4ab2-9ebc-71902777a8be)

)

---

## 📋 Activity Logs Dashboard

A clear and filterable activity log is available in the WordPress admin dashboard:

![Activity Logs Panel](![Screenshot 2025-04-12 135047](https://github.com/user-attachments/assets/25f05380-22c5-4add-a17b-c315d0ff5aaa)
)

---

## 🧰 Tools Used

- PHP (custom plugin)
- WordPress Hooks/APIs
- WP Mail for alerts
- CSV logging

---

## 🚀 Installation

1. Clone or download this repository
2. Place `activity-logger-security-monitor` folder inside `/wp-content/plugins/`
3. Activate from WP Admin > Plugins
4. View logs from `Activity Logs` menu in the admin sidebar

---

## 📧 Contact

For queries or enhancements, feel free to reach out.

**Developer:** Yogeshwar Saini  
**Email:** yogismash123@gmail.com  
**GitHub:** [github.com/yogeshwar-saini](https://github.com/yogeshwar-saini)

---

