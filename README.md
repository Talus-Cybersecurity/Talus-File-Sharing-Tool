# Talus-File-Sharing-Tool

  

**Group members**

- Adam Secrest - adam.secrest@csu.fullerton.edu

- Joshua Pavon - jjpavon@csu.fullerton.edu

- Michelle Pham - mp28jam@csu.fullerton.edu

- Landon Patam - lcpatam@csu.fullerton.edu
  

**Project Description**

Talus is a context-aware, policy-driven file sharing tool designed to bridge the gap between enterprise-grade security and everyday consumer accessibility. By moving beyond static encryption, Talus implements the Principle of Least Privilege through a dynamic "middle-man" server that enforces sender-defined access criteria—such as IP whitelisting, device certification, and time-of-day restrictions—before releasing decryption keys. The system features a zero-knowledge architecture to ensure end-to-end privacy and integrates a Random Forest machine learning model that analyzes access logs in real-time to detect and block suspicious behavior with a 90% accuracy rate. Built with a lightweight user friendly interface and robust cryptographic standards like AES-256 and RSA-2048, Talus provides a sophisticated yet user-friendly defense against excessive permissions and unauthorized data access.


**Problem Statement**

While planning the security features of Talus, we identified some gaps in the current secure file sharing space: many effective solutions remain unavailable to the everyday consumer as they are locked behind steep paywalls, provide minimal access to features with the free version, or are difficult to setup and use. Aspects such as file encryption and temporary decryption in local memory are essential security features for storing personal information cryptographically. This prevents physical memory reading attacks and data integrity in the event where adversaries gain access to a physical desktop. Modern file encryption methods typically autofill or entirely bypass passwords in exchange for a more user-friendly experience; however, it is a design flaw due to lack of security beyond the login. Other, non-password saving file encryptors go too far in the other direction, where standard users cannot set up the file encryption software in an efficient manner.  

Another identified issue is Excessive Network Share, in which businesses may grant overly broad access to files, data, and permissions for the convenience of sharing files. Additionally, businesses are unaware of how to set proper limits on the shared files, leaving access open even after the shared data is no longer in use. By creating a file sharing system, users can see warnings and risks of full access sharing through user-friendly interface to determine who can access data and under what circumstances. As a result, Talus can detect when an unauthorized user or system is trying to access shared data and steps in to block it before any compromises.