🛡️ ScamShield – Android Security Application
ScamShield is an Android-based mobile security application designed to identify suspicious SMS messages and potentially malicious URLs. It combines rule-based analysis, external threat intelligence, local database storage, and Firebase cloud services to help users recognize potential scams and phishing threats.
📱 Project Overview
ScamShield provides automatic incoming SMS scanning and manual URL scanning. It analyzes suspicious patterns, calculates risk scores, and alerts users about potentially dangerous content.
✨ Features
1. User Authentication
User registration and login.
Firebase Authentication integration.
Email verification.
Forgot password functionality.
2. Automatic SMS Scanning
Detects incoming SMS using Android BroadcastReceiver.
Analyzes message content using predefined suspicious patterns.
Extracts URLs from incoming messages.
Analyzes extracted URLs separately.
3. Manual URL Scanner
Allows users to enter URLs manually.
Performs local rule-based URL analysis.
Integrates the URLhaus threat-intelligence API.
Processes API responses to identify matching malicious URL records.
4. Risk Assessment
Calculates numerical risk scores.
Classifies results into three categories:
LOW: 0–29
MODERATE: 30–59
HIGH: 60–100
Provides explanations for suspicious detections.
5. Security Notifications
Generates alerts for high-risk detections.
Provides access to scan history through notifications.
6. Scan History
Stores scan records locally using SQLite.
Displays scan records using RecyclerView.
Shows scanned content, risk score, risk level, explanation, and timestamp.
Allows users to view scan details and clear history.
7. Firebase Cloud Integration
Firebase Authentication for user accounts.
Cloud Firestore for individual scan records.
Firebase Realtime Database for summary statistics.
8. Background Synchronization
Uses Android WorkManager for background cloud synchronization.
Maintains unsynchronized records locally.
Supports retry handling when network connectivity becomes available.
9. Security Monitoring
Uses an Android Foreground Service to maintain an ongoing protection status notification.
Provides a protection control through application settings.
🛠️ Technologies Used
Technology
Purpose
Java
Application development
XML
User interface design
Android Studio
Development environment
Firebase Authentication
User authentication
Cloud Firestore
Cloud scan storage
Firebase Realtime Database
Dashboard statistics
SQLite
Local database
RecyclerView
Scan history display
WorkManager
Background synchronization
BroadcastReceiver
Incoming SMS detection
Foreground Service
Ongoing monitoring status
REST API
URLhaus integration
JSON
API response processing

🏗️ Application Architecture
The application follows a modular structure, separating user interface, scanning logic, database management, cloud synchronization, and Android background components.
Main Components
Component
Responsibility
MainActivity
Main dashboard and navigation
SmsReceiver
Incoming SMS detection
SmsScanner
SMS and extracted URL analysis
UrlScannerActivity
Manual URL scanning
UrlhausChecker
URLhaus API communication
ScanDatabaseHelper
SQLite database operations
ScanHistoryAdapter
RecyclerView data binding
FirestoreSyncWorker
Background cloud synchronization
SecurityMonitoringService
Foreground monitoring status
DashboardActivity
Statistics and connectivity status
AccountActivity
Account information

⚙️ Installation and Setup
Prerequisites
Android Studio
Android SDK compatible with the project
JDK compatible with the Gradle configuration
Firebase project
Internet connection for cloud services and API integration
Steps
Clone the repository:

git clone https://github.com/Anirban-2404/ScamShield.git

Open the project in Android Studio.
Configure Firebase:
Create or select a Firebase project.
Register the Android application.
Configure Firebase Authentication.
Enable Cloud Firestore.
Enable Firebase Realtime Database.
Add the appropriate Firebase configuration file.
Configure the URLhaus API authentication key using the project's expected configuration method. Do not commit private API keys to the repository.
Allow Gradle to synchronize the project dependencies.
Run the application on a compatible Android device or emulator.
🔍 Risk Classification
Risk Score
Risk Level
0–29
LOW
30–59
MODERATE
60–100
HIGH

The application uses predefined rules and scoring mechanisms. URLhaus provides additional threat-intelligence information for manual URL scanning.
🔐 Permissions
Depending on the Android version and enabled features, ScamShield may require permissions for:
Receiving SMS messages.
Internet access.
Notifications.
Foreground service operation.
Permissions are requested and managed according to Android platform requirements.
📸 Screenshots
Application screenshots will be added here.
Suggested screenshots:
Login and Registration
Main Dashboard
Manual URL Scanner
URLhaus API Result
Automatic SMS Scanning
High-Risk Notification
Scan History
Statistics Dashboard
Account Information
⚠️ Disclaimer
ScamShield is an educational Android security project. Its rule-based detection and threat-intelligence lookup cannot guarantee detection of every scam or malicious URL.
A URL not found in the URLhaus database should not automatically be considered safe.
👨‍💻 Developer
Anirban Majumder Joy
Khulna University of Engineering & Technology,
Bangladesh
📂 Repository
GitHub: https://github.com/Anirban-2404/ScamShield


