# NexoraGuard iOS — Xcode Setup Guide

## Requirements
- macOS 13+ with Xcode 15+
- iOS 16+ device or simulator
- Apple Developer account (free is fine for simulator)

---

## Step 1 — Create New Xcode Project

1. Open Xcode → **File → New → Project**
2. Choose **iOS → App**
3. Fill in:
   - Product Name: `NexoraGuard`
   - Bundle Identifier: `com.nexora.securityagent`
   - Interface: **SwiftUI**
   - Language: **Swift**
   - Minimum Deployments: **iOS 16.0**
4. Save to: `ai-security-agent/ios/`

---

## Step 2 — Replace generated files

Delete the auto-generated files Xcode created, then add all files from `NexoraGuard/`:

```
NexoraGuard/
├── App/
│   ├── NexoraGuardApp.swift   ← replace ContentView.swift + App file
│   ├── AppDelegate.swift
│   ├── ContentView.swift
│   └── Info.plist             ← replace generated Info.plist
├── Models/
│   └── Models.swift
├── Services/
│   ├── APIService.swift
│   ├── AppPrefs.swift
│   ├── NotificationManager.swift
│   └── ThreatPollingManager.swift
└── Views/
    ├── Theme.swift
    ├── DashboardView.swift
    ├── ChatView.swift
    ├── AlertsView.swift
    ├── NetworkView.swift
    └── SettingsView.swift
```

In Xcode:
- Right-click project → **Add Files to "NexoraGuard"**
- Select all the folders above
- Check **"Create groups"** and **"Copy items if needed"**

---

## Step 3 — Info.plist settings

The `Info.plist` already includes:
- `NSAppTransportSecurity` → allows HTTP to local IPs (needed for backend)
- `NSUserNotificationsUsageDescription` → threat notifications
- `NSLocalNetworkUsageDescription` → local network access

---

## Step 4 — Configure server IP

In **Settings tab** of the app (or directly in `AppPrefs.swift`):
```swift
static let defaultURL = "http://YOUR_PC_IP:8000/"
```

---

## Step 5 — Run

- Simulator: just press ▶ in Xcode
- Real device: requires Apple Developer account (even free tier works)

---

## App Structure

| Tab       | View                 | Features |
|-----------|----------------------|----------|
| Dashboard | `DashboardView`      | Risk card, system stats, scan button, recent alerts, pull-to-refresh |
| AI Chat   | `ChatView`           | Full conversation history, quick prompts, typing indicator |
| Alerts    | `AlertsView`         | Filter by CRITICAL/HIGH/MEDIUM/LOW, pull-to-refresh |
| Network   | `NetworkView`        | All connections, suspicious filter, upload/download stats |
| Settings  | `SettingsView`       | Server URL + test, notification toggle, poll interval slider |

## Background Notifications
- `ThreatPollingManager` polls `/status` every N seconds (configurable in Settings)
- When risk is HIGH or CRITICAL: fires a local push notification
- Works even when app is in background (iOS background app refresh)
