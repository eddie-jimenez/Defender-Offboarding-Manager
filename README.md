# Defender Offboarding Manager
<img width="250" height="266" alt="shield" src="https://github.com/user-attachments/assets/0bc8e88d-2482-41ad-aac9-36a1246ac717" />


**Purpose**  
A macOS SwiftUI application for managing Microsoft Defender for Endpoint (MDE) device offboarding.  
This tool provides a user-friendly interface to search, view, and offboard Windows devices from MDE, with support for bulk operations, favorites, and comprehensive device information including logon users.

<img width="1039" height="652" alt="image" src="https://github.com/user-attachments/assets/1dd3beeb-1ef4-4f6c-8bd8-3cae39a0d880" />


**Created by:** Eddie Jimenez  
**Created on:** 2025-08-05  
**Version:** 1.0.0

---

## ✨ Features
- OAuth2 authentication with Microsoft identity platform
- Device search with real-time results
- Bulk device selection and offboarding (Windows only)
- Favorite devices for quick access
- Recent search history
- Comprehensive device information display
- Logon users information for each device
- Dashboard with statistics and quick actions
- Export device data to CSV
- Clean, modern macOS-native UI

<img width="2073" height="1954" alt="2025-08-08_11-23-06" src="https://github.com/user-attachments/assets/559bc597-df10-4742-b7c9-b64a550fa490" />





---

## 🚀 Usage
1. Launch the application.
2. Click **Sign In with Microsoft** to authenticate.
3. Use the sidebar navigation to access different features:
   - **Device Search** — Search and offboard individual devices
   - **All Devices** — View and manage all devices with bulk operations
   - **Favorites** — Quick access to frequently managed devices
   - **Recent Searches** — Access your search history
   - **Dashboard** — Overview and statistics
   - **Settings** — Account and data management

---  

## ⚠️ Important Configuration Required

Before using this application, you must configure the following:

### 1. Azure App Registration
- Create an app registration in Azure AD.
- Configure redirect URI:  
  ```
  msauth.com.defender.offboarder://auth
  ```
  *(Or your custom URI)*
- Grant API permissions:
  - **Microsoft Graph:** `User.Read.All`
  - **WindowsDefenderATP:** `Machine.Read`, `Machine.Offboard`
- Scope to appropriate users.

### 2. Update `DefenderAuthManager` Constants
- `clientId` — Your Azure app registration Client ID
- `tenantId` — Your Azure tenant ID
- `redirect_uri` — Your configured redirect URI  
  *(Appears in **5 places**, including the `Info.plist` and the Info tab on the target. Don’t forget to update both.)*

---

## 📋 Requirements
- macOS **13.5** or later
- Swift **5.5** or later
- Xcode **13.0** or later
- Active Microsoft Defender for Endpoint subscription
- Appropriate permissions in MDE to offboard devices

---

## 🔒 Security Notes
- Uses OAuth2 authorization code flow (**no client secret required**)
- Access tokens stored **in memory only** (not persisted)
- All API calls use **HTTPS**
- No sensitive data is logged or cached to disk

---

## 🌐 API Endpoints Used
- **Authorization:**  
  `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize`
- **Token:**  
  `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`
- **Devices:**  
  `https://api.security.microsoft.com/api/machines`
- **Logon Users:**  
  `https://api.security.microsoft.com/api/machines/{deviceId}/logonusers`
- **Offboard:**  
  `https://api.security.microsoft.com/api/machines/{deviceId}/offboard`

---

## ⚠️ Known Limitations
- Maximum **5,000** devices can be loaded at once (API limitation)
- Bulk offboarding processes devices sequentially
- Export function requires macOS file system access

---

## 🛠 Troubleshooting
- **Authentication fails:** Verify Azure app registration settings
- **Redirect URI mismatch:** Ensure it matches exactly in Azure and the code
- **Missing permissions:** Check API permissions are granted and admin consented
- **HTTP 403 errors:** Verify offboarding permissions in MDE
- **Redirect issues in build:** Ensure `Info.plist` and target Info tab both include the redirect URI

---

## 📜 Modification History
- **v1.0.0** — Initial release with core functionality
