# 🛡️ Activity Logger & Security Monitor

A custom WordPress plugin developed to monitor employee activities and enhance security on WordPress websites. It logs critical actions, detects suspicious behaviors, and sends real-time email alerts for security anomalies.

---

## 🔍 Key Features

- ✅ Tracks and logs all employee/user activities
- ✅ Detects suspicious behavior and file changes
- ✅ Sends real-time email alerts for critical security events
- ✅ Provides admin dashboard with categorized logs
- ✅ Exportable logs in CSV format
![ChatGPT Image Apr 12, 2025, 01_44_39 PM](https://github.com/user-attachments/assets/ab3c7474-846e-4f33-addd-a4462bd8f8ec)

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
![Screenshot 2025-04-12 134946](https://github.com/user-attachments/assets/805dd715-62a4-4c32-b3da-a8b66dd9ba41)


---

## 🚀 Tech Stack

### Core Technologies

<div align="center">

![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white)
![WordPress](https://img.shields.io/badge/WordPress-21759B?style=for-the-badge&logo=wordpress&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![REST API](https://img.shields.io/badge/REST_API-009688?style=for-the-badge&logo=fastapi&logoColor=white)

</div>

### 📊 Project Stats

<div align="center">

![Version](https://img.shields.io/badge/Version-v9.0-brightgreen?style=flat-square)
![WordPress](https://img.shields.io/badge/WordPress-5.6+-blue?style=flat-square)
![PHP](https://img.shields.io/badge/PHP-7.4+-purple?style=flat-square)
![License](https://img.shields.io/badge/License-GPL--2.0-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)

**9+ Classes** • **3K+ Lines of Code** • **50+ Functions** • **Unlimited Sites Support**

</div>

### 🎯 WordPress Integration

| Technology | Purpose |
|------------|---------|
| 🔌 **Plugin API** | WordPress hooks & filters |
| 🔑 **App Passwords** | Secure authentication |
| ⏰ **WP Cron** | Automated scheduled tasks |
| 💾 **Options API** | Settings & data storage |
| 📱 **REST API** | Inter-site communication |
| ⚡ **AJAX** | Real-time updates |

### ✨ Key Features

<table>
<tr>
<td width="50%">

#### 🔒 Security Management
- File editor control
- Version hiding
- File protection
- Auto IP blocking (4 failed attempts)

</td>
<td width="50%">

#### 📊 Monitoring & Alerts
- Real-time uptime monitoring
- SSL certificate tracking
- Smart notification system
- Activity logging

</td>
</tr>
<tr>
<td width="50%">

#### ⚙️ Site Management
- Plugin management
- Theme management
- Post & page control
- Bulk operations

</td>
<td width="50%">

#### ⏱️ Automation
- 5-minute uptime checks
- Hourly security scans
- Automated backups
- Scheduled tasks

</td>
</tr>
</table>

### 🛠️ Technical Architecture

```
┌─────────────────────────────────────────┐
│         Main WordPress Site             │
│     (Central Management Dashboard)      │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴───────┐
       │   REST API    │
       │ Communication │
       └───────┬───────┘
               │
    ┌──────────┼──────────┐
    │          │          │
┌───▼───┐  ┌──▼────┐  ┌──▼────┐
│Site 1 │  │Site 2 │  │Site N │
│Plugin │  │Plugin │  │Plugin │
└───────┘  └───────┘  └───────┘
```

### 📦 Dependencies

- **PHP**: 7.4 or higher
- **WordPress**: 5.6 or higher
- **MySQL**: 5.6 or higher
- **cURL**: For REST API communication
- **WP-Cron**: For automated tasks

---

<div align="center">

## 📧 Contact

For queries or enhancements, feel free to reach out.

**Developer:** Yogeshwar Saini
**Email:** yogismash123@gmail.com
**GitHub:** [github.com/yogeshwar-saini](https://github.com/yogeshwar-saini)



**Built with ❤️ for WordPress Security & Management**

</div>
