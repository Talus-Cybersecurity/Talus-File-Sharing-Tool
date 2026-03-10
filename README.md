# Talus File Sharing Tool

Talus is a **context-aware, policy-driven file sharing system** designed to bring enterprise-level security to everyday users. By combining modern encryption with dynamic access policies and machine learning–based threat detection, Talus ensures that shared files remain secure, private, and accessible only under approved conditions.

---

# Team Members

| Name | Email |
|-----|-----|
| Adam Secrest | adam.secrest@csu.fullerton.edu |
| Joshua Pavon | jjpavon@csu.fullerton.edu |
| Michelle Pham | mp28jam@csu.fullerton.edu |
| Landon Patam | lcpatam@csu.fullerton.edu |

---
  
# Dependencies

Talus currently relies on a small set of Python libraries to support secure communication and cryptographic operations. As the project evolves, additional dependencies will be added to support machine learning, logging, and expanded security features.

Current dependencies:

| Library | Purpose |
|-------|-------|
| websockets | Enables real-time communication between the client and Talus server |
| cryptography | Provides secure cryptographic primitives such as encryption, decryption, and key management |

These dependencies can be installed using:

```bash
pip install websockets cryptography
```

**Project Description**

Talus is a **secure file sharing platform** that bridges the gap between enterprise-grade security and consumer accessibility.

Traditional file sharing tools rely on **static encryption**, which protects files during transfer but offers limited control over how files are accessed after sharing. Talus enhances this model by implementing the **Principle of Least Privilege** through a dynamic **middle-man server** that enforces sender-defined access conditions before releasing decryption keys.

These conditions may include:

- IP address whitelisting
- Device certification
- Time-of-day access restrictions
- User authentication verification

Talus also utilizes a **zero-knowledge architecture**, ensuring that the server never has access to plaintext files or decryption keys.

To further strengthen security, Talus integrates a **Random Forest machine learning model** that analyzes access logs in real time to detect suspicious behavior. The model currently achieves approximately **90% accuracy** in identifying anomalous access attempts and can automatically block potential threats.

By combining:

- **AES-256 symmetric encryption**
- **RSA-2048 key exchange**
- **Machine learning threat detection**
- **Policy-based access control**

Talus provides a **secure yet user-friendly file sharing experience**.

---

# Problem Statement

While researching secure file sharing platforms, we identified several key gaps in existing solutions.

Many enterprise-grade systems provide strong security but suffer from one or more of the following issues:

- High subscription costs
- Limited features in free versions
- Complex configuration processes
- Poor usability for non-technical users

Basic security practices such as **file encryption and temporary in-memory decryption** are critical for protecting sensitive information. These measures help prevent attacks such as:

- Physical memory reading
- Unauthorized local access
- Data persistence after use

However, many modern systems prioritize convenience over security. For example, password managers or operating systems may automatically fill or bypass encryption passwords, creating potential vulnerabilities if a device becomes compromised.

On the other end of the spectrum, some encryption tools require complex manual setup that typical users struggle to configure correctly.

Another common issue is **Excessive Network Share**, where organizations grant overly broad access permissions for the sake of convenience. This often results in:

- Files remaining accessible long after they are needed
- Sensitive data being visible to unintended users
- Lack of visibility into who accesses shared data

Talus addresses these challenges by providing **clear policy controls and real-time security monitoring**. Through an intuitive interface, users can define **who can access files and under what conditions**, while the system monitors activity and automatically blocks suspicious access attempts.

---

# Key Features

- Policy-driven secure file sharing
- End-to-end encryption
- Zero-knowledge architecture
- Machine learning anomaly detection
- Sender-controlled access restrictions
- User-friendly interface for defining access policies

---

# Technologies Used

- **Encryption:** AES-256, RSA-2048  
- **Machine Learning:** Random Forest Classifier  
- **Backend:** Server Certification and RSA Key Exchanges
- **Frontend:** Client-end UI for Ease of Use
- **Logging & Monitoring:** Real-time access log analysis  

---

# System Architecture

Talus uses a **secure middle-man architecture** where the server enforces policies but never has access to decrypted data.

Basic flow:

1. Sender encrypts file locally.
2. File is uploaded to Talus server.
3. Access policies are attached to the file.
4. Recipient requests access.
5. Server verifies policy conditions.
6. If approved, the decryption key is released.
7. Machine learning system monitors access patterns for anomalies.
