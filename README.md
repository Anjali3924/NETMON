NetMon – Intelligent Network Monitoring & Intrusion Detection System
====================================================================

Summary
=======

This project (NetMon) is an intelligent Network Monitoring and Intrusion Detection System (IDS) that uses Machine Learning to analyze network traffic and detect suspicious or malicious activities.

The system simulates real-time network monitoring by combining:
- Traffic analysis
- Machine learning-based prediction
- Real-time dashboard visualization

The model is trained using the UNSW-NB15 dataset, which contains modern network traffic with labeled attack categories. Network-related insights such as IP behavior are analyzed using Wireshark.

The application is developed and executed using PyCharm IDE.


Usage License
=============

This project is developed for educational and research purposes.

- No guarantee is provided regarding the accuracy or completeness of the system.
- The system is provided "as is" without any warranty.
- Users may modify and use the project for learning and academic work.
- Commercial use is not intended without proper modifications and permissions.


Citation
========

If you use this project or dataset in academic work, please refer to:

> UNSW-NB15 Dataset: https://research.unsw.edu.au/projects/unsw-nb15-dataset

> Wireshark Tool: https://www.wireshark.org/

> PyCharm IDE: https://www.jetbrains.com/pycharm/


Further Information
===================

NetMon is designed to demonstrate concepts in:
- Cybersecurity
- Intrusion Detection Systems (IDS)
- Machine Learning in network security
- Real-time data visualization

The system mimics real-world cybersecurity dashboards used in industry.


Content and Use of System
========================

System Workflow
---------------

The system performs the following steps:

1. Collects network-related data (simulated or dataset-based)
2. Processes and cleans the data
3. Sends data to a Machine Learning model
4. Classifies traffic into categories
5. Displays results on a real-time dashboard

Architecture:
-------------

    Frontend (Dashboard UI)
            ↓
    Backend / API Layer
            ↓
    Machine Learning Model
            ↓
    Data Processing + Alerts


Formatting and Data Handling
----------------------------

- Data is handled in CSV format
- Preprocessing includes:
  - Cleaning missing values
  - Feature selection
  - Encoding categorical data
- Model input is structured numerical data
- Output is classification labels

All data processing is performed using Python libraries.


Dataset Information
===================

This project uses the UNSW-NB15 dataset for training and testing the Machine Learning model.

Dataset File:
-------------
- `UNSW-NB15_1.csv`

Dataset Link:
-------------
https://research.unsw.edu.au/projects/unsw-nb15-dataset

Dataset Description:
--------------------
The UNSW-NB15 dataset contains synthetic network traffic with labeled normal and malicious activities.

It includes:
- Normal traffic
- Multiple attack types such as:
  - DoS
  - Exploits
  - Fuzzers
  - Reconnaissance
  - Generic attacks

Features:
---------
- Source and destination IP
- Protocol type
- Packet size and duration
- Traffic statistics
- Connection states

Target Variable:
----------------
- Label indicating:
  - Normal traffic
  - Attack category


Machine Learning Model
======================

The Machine Learning model is used for classification of network traffic.

Input:
------
- Network features from dataset

Output:
-------
- Normal
- Suspicious
- Malicious

The model helps in identifying potential threats in real-time.


Intrusion Detection System (IDS)
================================

The IDS module is responsible for detecting abnormal network behavior.

Working:
--------
- Monitors traffic patterns
- Detects anomalies such as:
  - High packet rate
  - Unknown devices
  - Unusual behavior
- Sends data to ML model for classification

Output:
-------
- Threat classification
- Severity levels:
  - Low
  - Medium
  - High


Network Traffic Analysis (Wireshark)
====================================

Wireshark is used for capturing and analyzing network packets.

Tool Link:
----------
https://www.wireshark.org/

Usage:
------
- Capture live packets
- Extract IP addresses
- Analyze traffic behavior
- Understand real-world network patterns


Development Environment
======================

The project is developed using PyCharm IDE.

Tool Link:
----------
https://www.jetbrains.com/pycharm/

Usage:
------
- Code development
- Debugging
- Integration with ML libraries
- Project management


Dashboard and Visualization
===========================

The system provides a real-time dashboard with:

- Security status indicators
- Alerts and notifications
- Traffic statistics (packets/sec, threats/sec)
- Charts and visual analytics
- Device inventory

Color Indicators:
-----------------
- Green → Safe
- Yellow → Warning
- Red → Danger


Alerts and Logging
==================

Alerts Table:
-------------
- Displays detected threats
- Severity-based color coding

History:
--------
- Stores past activity
- Helps in analysis and pattern detection


Advantages
==========

- Real-time monitoring system
- Machine Learning-based detection
- User-friendly interface
- Scalable architecture
- Demonstrates practical cybersecurity concepts


Limitations
===========

- Uses simulated data instead of live capture
- Model accuracy depends on training data
- Not deployed in a real network environment


Future Enhancements
===================

- Integration with real-time packet sniffers
- Use of deep learning models
- Automated threat blocking
- Email/SMS alert system
- Cloud deployment


Conclusion
==========

NetMon demonstrates how Machine Learning and real-time analytics can be combined to detect and visualize network threats effectively.

It integrates monitoring, prediction, and visualization into a single intelligent cybersecurity system.


Author
======
- Anjali Kumawat
- Sarthak Mohite
