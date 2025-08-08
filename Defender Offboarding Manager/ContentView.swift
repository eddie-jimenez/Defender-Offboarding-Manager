//
//  Defender Offboarding Manager
//
//  Purpose: A macOS SwiftUI application for managing Microsoft Defender for Endpoint (MDE) device offboarding.
//           This tool provides a user-friendly interface to search, view, and offboard devices from MDE,
//           with support for bulk operations, favorites, and comprehensive device information including logon users.
//
//  Created by: Eddie Jimenez
//  Created on: 8/5/25
//  Version: 1.0.0
//
//
//  IMPORTANT CONFIGURATION REQUIRED:
//  Before using this application, you must configure the following:
//
//  1. Azure App Registration:
//     - Create an app registration in Azure AD
//     - Configure redirect URI: msauth.com.defender.offboarder://auth (or your custom URI)
//     - Grant API permissions:
//       • Microsoft Graph: User.Read.All
//       • WindowsDefenderATP: Machine.Read, Machine.Offboard
//     - Scope to appropriate users
//
//  2. Update the following constants in DefenderAuthManager class:
//     - clientId: Your Azure app registration Client ID
//     - tenantId: Your Azure tenant ID
//     - redirect_uri: Your configured redirect URI (appears in 5 places including the info.plist and info tab on the target. Don't forget to update the info.plist and info tab on the target!)
//
//  FEATURES:
//  - OAuth2 authentication with Microsoft identity platform
//  - Device search with real-time results
//  - Bulk device selection and offboarding
//  - Favorite devices for quick access
//  - Recent search history
//  - Comprehensive device information display
//  - Logon users information for each device
//  - Dashboard with statistics and quick actions
//  - Export device data to CSV
//  - Clean, modern macOS-native UI
//
//  REQUIREMENTS:
//  - macOS 13.5 or later
//  - Swift 5.5 or later
//  - Xcode 13.0 or later
//  - Active Microsoft Defender for Endpoint subscription
//  - Appropriate permissions in MDE to offboard devices
//
//  SECURITY NOTES:
//  - This app uses OAuth2 authorization code flow (no client secret required)
//  - Access tokens are stored in memory only (not persisted)
//  - All API calls use HTTPS
//  - No sensitive data is logged or cached to disk
//
//  API ENDPOINTS USED:
//  - Authorization: https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize
//  - Token: https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token
//  - Devices: https://api.security.microsoft.com/api/machines
//  - Logon Users: https://api.security.microsoft.com/api/machines/{deviceId}/logonusers
//  - Offboard: https://api.security.microsoft.com/api/machines/{deviceId}/offboard
//
//  USAGE:
//  1. Launch the application
//  2. Click "Sign In with Microsoft" to authenticate
//  3. Use the sidebar navigation to access different features:
//     - Device Search: Search and offboard individual devices
//     - All Devices: View and manage all devices with bulk operations
//     - Favorites: Quick access to frequently managed devices
//     - Recent Searches: Access your search history
//     - Dashboard: Overview and statistics
//     - Settings: Account and data management
//
//  KNOWN LIMITATIONS:
//  - Maximum 5000 devices can be loaded at once (API limitation)
//  - Bulk offboarding processes devices sequentially
//  - Export function requires macOS file system access
//
//  TROUBLESHOOTING:
//  - If authentication fails, verify your Azure app registration settings
//  - Ensure redirect URI matches exactly in both Azure and the code
//  - Check that all required API permissions are granted and admin consented
//  - For HTTP 403 errors, verify your account has offboarding permissions in MDE
//  - Ensure all package build settings and the info.plist include the redirect URI
//
//  MODIFICATION HISTORY:
//  - v1.0.0: Initial release with core functionality
//

import SwiftUI
import Foundation
import AuthenticationServices

#if canImport(AppKit)
import AppKit
#endif

// MARK: - Models and Data Structures

struct DefenderLogonUser: Identifiable, Codable {
    let id: String
    let accountName: String
    let accountDomain: String
    let firstSeen: String
    let lastSeen: String
    let logonTypes: String
    let isDomainAdmin: Bool
    let isOnlyNetworkUser: Bool
    
    enum CodingKeys: String, CodingKey {
        case id
        case accountName
        case accountDomain
        case firstSeen
        case lastSeen
        case logonTypes
        case isDomainAdmin
        case isOnlyNetworkUser
    }
    
    var displayName: String {
        if accountDomain.isEmpty {
            return accountName
        } else {
            return "\(accountDomain)\\\(accountName)"
        }
    }
}

struct DefenderDevice: Identifiable, Codable {
    let id: String
    let computerDnsName: String
    let aadDeviceId: String?
    let healthStatus: String
    let osPlatform: String
    let lastSeen: String
    var logonUsers: [DefenderLogonUser] = []
    var usersLoaded: Bool = false
    
    enum CodingKeys: String, CodingKey {
        case id
        case computerDnsName
        case aadDeviceId
        case healthStatus
        case osPlatform
        case lastSeen
    }
}

// MARK: - Authentication Manager

class DefenderAuthManager: NSObject, ObservableObject {
    @Published var isAuthenticated = false
    @Published var accessToken: String?
    @Published var isLoading = false
    @Published var errorMessage: String?
    
    // Using the same Azure PowerShell client ID as the original script - no secret needed for interactive auth
    private let clientId = "YOUR CLIENT ID" // App registration ClientID
    private let tenantId = "YOUR TENANT ID" // Replace with your actual tenant ID
    private let scopes = [
        "https://api.securitycenter.microsoft.com/Machine.Read",
        "https://api.securitycenter.microsoft.com/Machine.Offboard",
        "User.Read.All"
    ]
    
    func authenticate() {
        isLoading = true
        errorMessage = nil
        
        // Construct the Microsoft OAuth2 authorization URL
        var components = URLComponents(string: "https://login.microsoftonline.com/\(tenantId)/oauth2/v2.0/authorize")!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: "YOUR REDIRECT URI"),  // Your redirect URI example: msauth.com.defender.offboarder://auth
            URLQueryItem(name: "scope", value: scopes.joined(separator: " ")),
            URLQueryItem(name: "response_mode", value: "query"),
            URLQueryItem(name: "state", value: UUID().uuidString),
            URLQueryItem(name: "prompt", value: "select_account") // oauth login window
        ]
        
        guard let authURL = components.url else {
            DispatchQueue.main.async {
                self.errorMessage = "Failed to create authentication URL"
                self.isLoading = false
            }
            return
        }
        
        // Start the authentication session using ASWebAuthenticationSession
        let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: "YOUR REDIRECT URI") { [weak self] url, error in // Your redirect URI example: msauth.com.defender.offboarder://auth
            DispatchQueue.main.async {
                self?.handleAuthCallback(url: url, error: error)
            }
        }
        
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        session.start()
    }
    
    private func handleAuthCallback(url: URL?, error: Error?) {
        isLoading = false
        
        if let error = error {
            if (error as NSError).code == ASWebAuthenticationSessionError.canceledLogin.rawValue {
                errorMessage = "Authentication was cancelled"
            } else {
                errorMessage = "Authentication failed: \(error.localizedDescription)"
            }
            return
        }
        
        guard let url = url,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            errorMessage = "Invalid callback URL"
            return
        }
        
        // Check for error in callback
        if (queryItems.first(where: { $0.name == "error" })?.value) != nil {
            let errorDescription = queryItems.first(where: { $0.name == "error_description" })?.value ?? "Unknown error"
            errorMessage = "Authentication error: \(errorDescription)"
            return
        }
        
        // Extract the authorization code
        guard let code = queryItems.first(where: { $0.name == "code" })?.value else {
            errorMessage = "No authorization code received"
            return
        }
        
        // Exchange authorization code for access token
        exchangeCodeForToken(code: code)
    }
    
    private func exchangeCodeForToken(code: String) {
        isLoading = true
        
        guard let tokenURL = URL(string: "https://login.microsoftonline.com/\(tenantId)/oauth2/v2.0/token") else {
            errorMessage = "Invalid token URL"
            isLoading = false
            return
        }
        
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let bodyParameters = [
            "client_id": clientId,
            "scope": scopes.joined(separator: " "),
            "code": code,
            "redirect_uri": "YOUR REDIRECT URI", // Your redirect URI example: msauth.com.defender.offboarder://auth
            "grant_type": "authorization_code"
        ]
        
        let bodyString = bodyParameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }
            .joined(separator: "&")
        
        request.httpBody = bodyString.data(using: .utf8)
        
        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                self?.handleTokenResponse(data: data, response: response, error: error)
            }
        }.resume()
    }
    
    private func handleTokenResponse(data: Data?, response: URLResponse?, error: Error?) {
        isLoading = false
        
        if let error = error {
            errorMessage = "Token exchange failed: \(error.localizedDescription)"
            return
        }
        
        guard let data = data else {
            errorMessage = "No response data received"
            return
        }
        
        do {
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                errorMessage = "Invalid response format"
                return
            }
            
            if json["error"] is String {
                let errorDescription = json["error_description"] as? String ?? "Unknown error"
                errorMessage = "Token error: \(errorDescription)"
                return
            }
            
            guard let token = json["access_token"] as? String else {
                errorMessage = "No access token in response"
                return
            }
            
            // Successfully received access token
            accessToken = token
            isAuthenticated = true
            errorMessage = nil
            
        } catch {
            errorMessage = "Failed to parse token response: \(error.localizedDescription)"
        }
    }
    
    func signOut() {
        accessToken = nil
        isAuthenticated = false
        errorMessage = nil
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension DefenderAuthManager: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if canImport(AppKit)
        return NSApplication.shared.windows.first ?? ASPresentationAnchor()
        #else
        return ASPresentationAnchor()
        #endif
    }
}

// MARK: - API Manager

class DefenderAPIManager: NSObject, ObservableObject {
    @Published var devices: [DefenderDevice] = []
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var recentSearches: [String] = []
    @Published var favoriteDevices: [DefenderDevice] = []
    
    // Track loading state for individual devices
    @Published var devicesLoadingUsers: Set<String> = []
    private var loadedDeviceUsers: Set<String> = []
    
    private let baseURL = "https://api.security.microsoft.com/api"
    
    var deviceStats: [String: Int] {
        let groupedByStatus = Dictionary(grouping: devices, by: { $0.healthStatus })
        return groupedByStatus.mapValues { $0.count }
    }
    
    var platformStats: [String: Int] {
        let groupedByPlatform = Dictionary(grouping: devices, by: { $0.osPlatform })
        return groupedByPlatform.mapValues { $0.count }
    }
    
    func addRecentSearch(_ deviceName: String) {
        if !recentSearches.contains(deviceName) {
            recentSearches.insert(deviceName, at: 0)
            if recentSearches.count > 10 {
                recentSearches.removeLast()
            }
        }
    }
    
    func toggleFavorite(_ device: DefenderDevice) {
        if let index = favoriteDevices.firstIndex(where: { $0.id == device.id }) {
            favoriteDevices.remove(at: index)
        } else {
            favoriteDevices.append(device)
        }
    }
    
    func isFavorite(_ device: DefenderDevice) -> Bool {
        favoriteDevices.contains(where: { $0.id == device.id })
    }
    
    func fetchAllDevices(accessToken: String) {
        isLoading = true
        errorMessage = nil
        devices = [] // Clear existing devices
        loadedDeviceUsers.removeAll() // Clear loaded users tracking
        
        let apiURL = "\(baseURL)/machines?$Select=id,computerDnsName,aadDeviceId,healthStatus,osPlatform,lastSeen"
        fetchDevicesPage(accessToken: accessToken, url: apiURL)
    }
    
    private func fetchDevicesPage(accessToken: String, url: String) {
        guard let requestURL = URL(string: url) else {
            DispatchQueue.main.async {
                self.errorMessage = "Invalid API URL"
                self.isLoading = false
            }
            return
        }
        
        var request = URLRequest(url: requestURL)
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                self?.handleDevicesResponse(data: data, response: response, error: error, accessToken: accessToken)
            }
        }.resume()
    }
    
    private func handleDevicesResponse(data: Data?, response: URLResponse?, error: Error?, accessToken: String) {
        if let error = error {
            errorMessage = "API request failed: \(error.localizedDescription)"
            isLoading = false
            return
        }
        
        guard let httpResponse = response as? HTTPURLResponse else {
            errorMessage = "Invalid response"
            isLoading = false
            return
        }
        
        guard httpResponse.statusCode == 200 else {
            errorMessage = "API returned status code: \(httpResponse.statusCode)"
            isLoading = false
            return
        }
        
        guard let data = data else {
            errorMessage = "No data received from API"
            isLoading = false
            return
        }
        
        do {
            // Parse the response
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            
            guard let deviceArray = json?["value"] as? [[String: Any]] else {
                errorMessage = "Invalid response format - no 'value' array"
                isLoading = false
                return
            }
            
            // Convert JSON to DefenderDevice objects
            var newDevices: [DefenderDevice] = []
            for deviceData in deviceArray {
                if let device = parseDevice(from: deviceData) {
                    newDevices.append(device)
                }
            }
            
            devices.append(contentsOf: newDevices)
            
            // Check if there are more pages (@odata.nextLink)
            if let nextLink = json?["@odata.nextLink"] as? String {
                fetchDevicesPage(accessToken: accessToken, url: nextLink)
            } else {
                isLoading = false
            }
            
        } catch {
            errorMessage = "Failed to parse API response: \(error.localizedDescription)"
            isLoading = false
        }
    }
    
    private func parseDevice(from data: [String: Any]) -> DefenderDevice? {
        guard let id = data["id"] as? String,
              let computerDnsName = data["computerDnsName"] as? String,
              let healthStatus = data["healthStatus"] as? String,
              let osPlatform = data["osPlatform"] as? String,
              let lastSeen = data["lastSeen"] as? String else {
            return nil
        }
        
        let aadDeviceId = data["aadDeviceId"] as? String
        
        return DefenderDevice(
            id: id,
            computerDnsName: computerDnsName,
            aadDeviceId: aadDeviceId,
            healthStatus: healthStatus,
            osPlatform: osPlatform,
            lastSeen: lastSeen,
            logonUsers: [],
            usersLoaded: false
        )
    }
    
    func searchDevice(deviceName: String) -> DefenderDevice? {
        return devices.first { $0.computerDnsName.lowercased() == deviceName.lowercased() }
    }
    
    func fetchLogonUsers(for deviceId: String, accessToken: String, completion: @escaping ([DefenderLogonUser]?, String?) -> Void) {
        guard let url = URL(string: "\(baseURL)/machines/\(deviceId)/logonusers") else {
            completion(nil, "Invalid logon users URL")
            return
        }
        
        var request = URLRequest(url: url)
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                if let error = error {
                    completion(nil, "Failed to fetch logon users: \(error.localizedDescription)")
                    return
                }
                
                guard let httpResponse = response as? HTTPURLResponse else {
                    completion(nil, "Invalid response")
                    return
                }
                
                guard httpResponse.statusCode == 200 else {
                    completion(nil, "API returned status code: \(httpResponse.statusCode)")
                    return
                }
                
                guard let data = data else {
                    completion(nil, "No data received from API")
                    return
                }
                
                do {
                    let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                    
                    guard let usersArray = json?["value"] as? [[String: Any]] else {
                        completion([], nil) // Return empty array if no users
                        return
                    }
                    
                    var logonUsers: [DefenderLogonUser] = []
                    for userData in usersArray {
                        if let user = self.parseLogonUser(from: userData) {
                            logonUsers.append(user)
                        }
                    }
                    
                    completion(logonUsers, nil)
                    
                } catch {
                    completion(nil, "Failed to parse logon users response: \(error.localizedDescription)")
                }
            }
        }.resume()
    }
    
    private func parseLogonUser(from data: [String: Any]) -> DefenderLogonUser? {
        guard let id = data["id"] as? String,
              let accountName = data["accountName"] as? String,
              let accountDomain = data["accountDomain"] as? String,
              let firstSeen = data["firstSeen"] as? String,
              let lastSeen = data["lastSeen"] as? String,
              let logonTypes = data["logonTypes"] as? String else {
            return nil
        }
        
        let isDomainAdmin = data["isDomainAdmin"] as? Bool ?? false
        let isOnlyNetworkUser = data["isOnlyNetworkUser"] as? Bool ?? false
        
        return DefenderLogonUser(
            id: id,
            accountName: accountName,
            accountDomain: accountDomain,
            firstSeen: firstSeen,
            lastSeen: lastSeen,
            logonTypes: logonTypes,
            isDomainAdmin: isDomainAdmin,
            isOnlyNetworkUser: isOnlyNetworkUser
        )
    }
    
    func fetchDeviceWithUsers(deviceId: String, accessToken: String, completion: @escaping (DefenderDevice?, String?) -> Void) {
        if let existingDevice = devices.first(where: { $0.id == deviceId }) {
            fetchLogonUsers(for: deviceId, accessToken: accessToken) { users, error in
                if let error = error {
                    completion(nil, error)
                } else {
                    var updatedDevice = existingDevice
                    updatedDevice.logonUsers = users ?? []
                    updatedDevice.usersLoaded = true
                    completion(updatedDevice, nil)
                }
            }
        } else {
            completion(nil, "Device not found in loaded devices")
        }
    }
    
    // Updated: Load users for specific device and update the devices array
    func loadUsersForDevice(deviceId: String, accessToken: String) {
        guard !devicesLoadingUsers.contains(deviceId),
              !loadedDeviceUsers.contains(deviceId) else { return }
        
        devicesLoadingUsers.insert(deviceId)
        
        fetchLogonUsers(for: deviceId, accessToken: accessToken) { [weak self] users, error in
            guard let self = self else { return }
            
            self.devicesLoadingUsers.remove(deviceId)
            
            if let users = users,
               let deviceIndex = self.devices.firstIndex(where: { $0.id == deviceId }) {
                self.devices[deviceIndex].logonUsers = users
                self.devices[deviceIndex].usersLoaded = true
                self.loadedDeviceUsers.insert(deviceId)
            }
        }
    }
    
    func offboardDevice(deviceId: String, accessToken: String, completion: @escaping (Bool, String?) -> Void) {
        guard let url = URL(string: "\(baseURL)/machines/\(deviceId)/offboard") else {
            completion(false, "Invalid offboard URL")
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Get current user for comment
        let currentUser = NSUserName()
        let requestBody = [
            "Comment": "Offboard machine by \(currentUser)"
        ]
        
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: requestBody)
        } catch {
            completion(false, "Failed to encode offboard request: \(error.localizedDescription)")
            return
        }
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                if let error = error {
                    completion(false, "Offboard request failed: \(error.localizedDescription)")
                    return
                }
                
                guard let httpResponse = response as? HTTPURLResponse else {
                    completion(false, "Invalid response")
                    return
                }
                
                if httpResponse.statusCode == 200 || httpResponse.statusCode == 201 || httpResponse.statusCode == 202 {
                    completion(true, nil)
                } else {
                    let statusMessage = "HTTP \(httpResponse.statusCode)"
                    if let data = data,
                       let errorResponse = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                       let errorDict = errorResponse["error"] as? [String: Any],
                       let errorMessage = errorDict["message"] as? String {
                        completion(false, "\(statusMessage): \(errorMessage)")
                    } else {
                        completion(false, "\(statusMessage): Offboard request failed")
                    }
                }
            }
        }.resume()
    }
}

// MARK: - Helper Views

struct InfoRow: View {
    let label: String
    let value: String
    var statusColor: Color? = nil
    
    var body: some View {
        HStack {
            Text(label + ":")
                .fontWeight(.medium)
                .frame(minWidth: 120, alignment: .leading)
            
            if let color = statusColor {
                HStack {
                    Circle()
                        .fill(color)
                        .frame(width: 8, height: 8)
                    Text(value)
                        .textSelection(.enabled)
                }
            } else {
                Text(value)
                    .textSelection(.enabled)
            }
            
            Spacer()
        }
    }
}

struct StatusBadge: View {
    let status: String
    
    var body: some View {
        Text(status)
            .font(.caption)
            .fontWeight(.medium)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(backgroundColor)
            .foregroundColor(foregroundColor)
            .clipShape(Capsule())
    }
    
    private var backgroundColor: Color {
        switch status.lowercased() {
        case "active":
            return .green.opacity(0.2)
        case "inactive":
            return .orange.opacity(0.2)
        default:
            return .gray.opacity(0.2)
        }
    }
    
    private var foregroundColor: Color {
        switch status.lowercased() {
        case "active":
            return .green
        case "inactive":
            return .orange
        default:
            return .gray
        }
    }
}

// MARK: - Inline User Display Component
struct InlineUserDisplay: View {
    let device: DefenderDevice
    let isLoading: Bool
    
    var body: some View {
        if isLoading {
            HStack {
                ProgressView()
                    .scaleEffect(0.6)
                Text("Loading users...")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        } else if let firstUser = device.logonUsers.first {
            HStack {
                Image(systemName: "person.circle.fill")
                    .foregroundColor(.blue)
                    .font(.caption)
                
                Text(firstUser.displayName)
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                if device.logonUsers.count > 1 {
                    Text("+ \(device.logonUsers.count - 1)")
                        .font(.caption2)
                        .foregroundColor(.gray)
                }
            }
        } else {
            HStack {
                Image(systemName: "person.slash")
                    .foregroundColor(.gray)
                    .font(.caption)
                Text("No users")
                    .font(.caption2)
                    .foregroundColor(.gray)
            }
        }
    }
}

// MARK: - Sidebar Components

struct SidebarView: View {
    @ObservedObject var authManager: DefenderAuthManager
    @ObservedObject var apiManager: DefenderAPIManager
    @Binding var selectedView: SidebarSection
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Image("shield")  // Shield icon
                        .resizable()
                        .scaledToFit()
                        .frame(width: 15, height: 15)  // Adjust size as needed
                    Text("Defender")
                        .font(.title2)
                        .fontWeight(.bold)
                }
                Text("Offboarding Manager")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.leading, 11)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            
            Divider()
            
            if authManager.isAuthenticated {
                // Navigation Items
                ScrollView {
                    LazyVStack(spacing: 2) {
                        SidebarItem(
                            icon: "magnifyingglass",
                            title: "Device Search",
                            isSelected: selectedView == .search,
                            action: { selectedView = .search }
                        )
                        
                        SidebarItem(
                            icon: "list.bullet",
                            title: "All Devices",
                            badge: apiManager.devices.count > 0 ? "\(apiManager.devices.count)" : nil,
                            isSelected: selectedView == .allDevices,
                            action: { selectedView = .allDevices }
                        )
                        
                        SidebarItem(
                            icon: "heart.fill",
                            title: "Favorites",
                            badge: apiManager.favoriteDevices.count > 0 ? "\(apiManager.favoriteDevices.count)" : nil,
                            isSelected: selectedView == .favorites,
                            action: { selectedView = .favorites }
                        )
                        
                        SidebarItem(
                            icon: "clock.fill",
                            title: "Recent Searches",
                            badge: apiManager.recentSearches.count > 0 ? "\(apiManager.recentSearches.count)" : nil,
                            isSelected: selectedView == .recent,
                            action: { selectedView = .recent }
                        )
                        
                        SidebarItem(
                            icon: "chart.bar.fill",
                            title: "Dashboard",
                            isSelected: selectedView == .dashboard,
                            action: { selectedView = .dashboard }
                        )
                        
                        Divider()
                            .padding(.vertical, 8)
                        
                        SidebarItem(
                            icon: "gear",
                            title: "Settings",
                            isSelected: selectedView == .settings,
                            action: { selectedView = .settings }
                        )
                    }
                }
                .padding(.vertical, 8)
                
                Spacer()
                
                // Status Footer
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Circle()
                            .fill(Color.green)
                            .frame(width: 8, height: 8)
                        Text("Connected")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    
                    if apiManager.devices.count > 0 {
                        Text("\(apiManager.devices.count) devices loaded")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 12)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Image(systemName: "lock.fill")
                        .font(.title)
                        .foregroundColor(.gray)
                    Text("Sign in to access your Defender devices")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.leading)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 20)
                
                Spacer()
            }
        }
        .frame(minWidth: 200, maxWidth: 250)
        .background(Color(.controlBackgroundColor))
    }
}

struct SidebarItem: View {
    let icon: String
    let title: String
    var badge: String? = nil
    let isSelected: Bool
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(isSelected ? .white : .primary)
                    .frame(width: 16)
                
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(isSelected ? .white : .primary)
                
                Spacer()
                
                if let badge = badge {
                    Text(badge)
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(isSelected ? .blue : .white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(isSelected ? .white : .blue)
                        .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .background(isSelected ? Color.blue : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(PlainButtonStyle())
        .padding(.horizontal, 8)
    }
}

enum SidebarSection: CaseIterable {
    case search, dashboard, favorites, recent, allDevices, settings
    
    var title: String {
        switch self {
        case .search: return "Device Search"
        case .dashboard: return "Dashboard"
        case .favorites: return "Favorites"
        case .recent: return "Recent Searches"
        case .allDevices: return "All Devices"
        case .settings: return "Settings"
        }
    }
}

// MARK: - Logon Users Components

struct LogonUsersSection: View {
    let device: DefenderDevice
    let isLoading: Bool
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Logon Users")
                    .font(.title3)
                    .fontWeight(.semibold)
                
                Spacer()
                
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.8)
                } else {
                    Text("\(device.logonUsers.count) users")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            if isLoading {
                HStack {
                    ProgressView()
                        .scaleEffect(0.8)
                    Text("Loading logon users...")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .center)
                .padding()
            } else if device.logonUsers.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "person.slash")
                        .font(.title2)
                        .foregroundColor(.gray)
                    Text("No logon users found")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .center)
                .padding()
            } else {
                VStack(spacing: 8) {
                    ForEach(device.logonUsers) { user in
                        LogonUserCard(user: user)
                    }
                }
            }
        }
        .padding()
        .background(Color(.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct LogonUserCard: View {
    let user: DefenderLogonUser
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(user.displayName)
                        .font(.subheadline)
                        .fontWeight(.medium)
                    Text(user.isOnlyNetworkUser ? "Network Only" : "Standard User")
                        .font(.caption)
                        .foregroundColor(user.isOnlyNetworkUser ? .orange : .secondary)
                }
                
                Spacer()
            }
            
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("First Seen:")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text(formatUserDate(user.firstSeen))
                        .font(.caption)
                }
                
                Spacer()
                
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Last Seen:")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text(formatUserDate(user.lastSeen))
                        .font(.caption)
                }
            }
            
            if !user.logonTypes.isEmpty {
                Text("Logon Types: \(user.logonTypes)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color.black.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
    
    private func formatUserDate(_ dateString: String) -> String {
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: dateString) {
            let displayFormatter = DateFormatter()
            displayFormatter.dateStyle = .short
            displayFormatter.timeStyle = .none
            return displayFormatter.string(from: date)
        }
        return dateString
    }
}

struct LogonUsersCompactSection: View {
    let device: DefenderDevice
    let isLoading: Bool
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Recent Users")
                    .font(.subheadline)
                    .fontWeight(.medium)
                
                Spacer()
                
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.6)
                } else if !device.logonUsers.isEmpty {
                    Text("\(device.logonUsers.count)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            if isLoading {
                HStack {
                    ProgressView()
                        .scaleEffect(0.6)
                    Text("Loading...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } else if device.logonUsers.isEmpty {
                Text("No recent users")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                // Show first 3 users in compact format
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(device.logonUsers.prefix(3))) { user in
                        HStack {
                            Text(user.displayName)
                                .font(.caption)
                                .fontWeight(.medium)
                            
                            Spacer()
                            
                            Text(user.isOnlyNetworkUser ? "Network Only" : "Standard")
                                .font(.system(size: 8))
                                .foregroundColor(.secondary)
                        }
                    }
                    
                    if device.logonUsers.count > 3 {
                        Text("+ \(device.logonUsers.count - 3) more users")
                            .font(.system(size: 8))
                            .foregroundColor(.secondary)
                            .italic()
                    }
                }
            }
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(Color.black.opacity(0.03))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

// MARK: - Dashboard View

struct DashboardView: View {
    @ObservedObject var apiManager: DefenderAPIManager
    @ObservedObject var authManager: DefenderAuthManager
    
    var body: some View {
        ScrollView {
            LazyVStack(spacing: 20) {
                // Header Stats
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 16), count: 3), spacing: 16) {
                    StatCard(
                        title: "Total Devices",
                        value: "\(apiManager.devices.count)",
                        icon: "desktopcomputer",
                        color: .blue
                    )
                    
                    StatCard(
                        title: "Active Devices",
                        value: "\(apiManager.deviceStats["Active"] ?? 0)",
                        icon: "checkmark.circle.fill",
                        color: .green
                    )
                    
                    StatCard(
                        title: "Inactive Devices",
                        value: "\(apiManager.deviceStats["Inactive"] ?? 0)",
                        icon: "exclamationmark.triangle.fill",
                        color: .orange
                    )
                }
                
                // Platform Distribution
                VStack(alignment: .leading, spacing: 12) {
                    Text("Platform Distribution")
                        .font(.headline)
                        .fontWeight(.semibold)
                    
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 2), spacing: 12) {
                        ForEach(Array(apiManager.platformStats.keys.sorted()), id: \.self) { platform in
                            PlatformCard(
                                platform: platform,
                                count: apiManager.platformStats[platform] ?? 0,
                                total: apiManager.devices.count
                            )
                        }
                    }
                }
                .padding(.horizontal)
                
                // Quick Actions
                VStack(alignment: .leading, spacing: 12) {
                    Text("Quick Actions")
                        .font(.headline)
                        .fontWeight(.semibold)
                    
                    HStack(spacing: 12) {
                        ActionButton(
                            title: "Refresh Devices",
                            icon: "arrow.clockwise",
                            color: .blue,
                            isLoading: apiManager.isLoading
                        ) {
                            if let token = authManager.accessToken {
                                apiManager.fetchAllDevices(accessToken: token)
                            }
                        }
                        
                        ActionButton(
                            title: "Export Data",
                            icon: "square.and.arrow.up",
                            color: .green
                        ) {
                            exportDeviceData()
                        }
                        
                        ActionButton(
                            title: "Clear Cache",
                            icon: "trash",
                            color: .red
                        ) {
                            apiManager.recentSearches.removeAll()
                            apiManager.favoriteDevices.removeAll()
                        }
                    }
                }
                .padding(.horizontal)
            }
            .padding(.vertical)
        }
    }
    
    private func exportDeviceData() {
        // Create CSV content
        var csvContent = "Device Name,Device ID,Health Status,OS Platform,Last Seen,AAD Device ID,First User\n"
        
        for device in apiManager.devices {
            let firstUser = device.logonUsers.first?.displayName ?? "No users"
            let aadId = device.aadDeviceId ?? "N/A"
            csvContent += "\"\(device.computerDnsName)\",\"\(device.id)\",\"\(device.healthStatus)\",\"\(device.osPlatform)\",\"\(device.lastSeen)\",\"\(aadId)\",\"\(firstUser)\"\n"
        }
        
        #if canImport(AppKit)
        // Create save panel
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = "defender_devices_export.csv"
        savePanel.allowedContentTypes = [.commaSeparatedText]
        
        savePanel.begin { result in
            if result == .OK, let url = savePanel.url {
                do {
                    try csvContent.write(to: url, atomically: true, encoding: .utf8)
                    // Optionally show success message
                } catch {
                    print("Failed to save file: \(error)")
                }
            }
        }
        #endif
    }
}

struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)
                Spacer()
            }
            
            Text(value)
                .font(.title)
                .fontWeight(.bold)
                .foregroundColor(.primary)
            
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .shadow(color: Color.black.opacity(0.05), radius: 2, x: 0, y: 1)
    }
}

struct PlatformCard: View {
    let platform: String
    let count: Int
    let total: Int
    
    private var percentage: Double {
        total > 0 ? Double(count) / Double(total) * 100 : 0
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: platformIcon)
                    .foregroundColor(.blue)
                Text(platform)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Spacer()
                Text("\(count)")
                    .font(.subheadline)
                    .fontWeight(.semibold)
            }
            
            ProgressView(value: percentage, total: 100)
                .tint(.blue)
            
            Text("\(String(format: "%.1f", percentage))%")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
    
    private var platformIcon: String {
        switch platform.lowercased() {
        case let p where p.contains("windows"):
            return "laptopcomputer"
        case let p where p.contains("mac"):
            return "desktopcomputer"
        case let p where p.contains("linux"):
            return "terminal"
        case let p where p.contains("embedded"):
            return "cpu"
        default:
            return "questionmark.circle"
        }
    }
}

struct ActionButton: View {
    let title: String
    let icon: String
    let color: Color
    var isLoading: Bool = false
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack {
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.8)
                } else {
                    Image(systemName: icon)
                }
                Text(title)
                    .fontWeight(.medium)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(color.opacity(0.1))
            .foregroundColor(color)
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(PlainButtonStyle())
        .disabled(isLoading)
    }
}

// MARK: - Individual View Components

struct AuthenticationView: View {
    @ObservedObject var authManager: DefenderAuthManager
    
    var body: some View {
        VStack(spacing: 30) {
            VStack(spacing: 16) {
                Image("shield")  // This will load shield.png from Assets.xcassets
                    .resizable()
                    .scaledToFit()
                    .frame(width: 128, height: 128)  // Adjust size as needed
                VStack(spacing: 8) {
                    Text("Defender")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                    
                    Text("Offboarding Manager")
                        .font(.title2)
                        .foregroundColor(.secondary)
                }
                
                Text("Manage your MDE devices securely and easily")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            
            VStack(spacing: 20) {
                if let errorMessage = authManager.errorMessage {
                    Text(errorMessage)
                        .foregroundColor(.red)
                        .multilineTextAlignment(.center)
                        .padding()
                        .background(Color.red.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                
                Button(action: {
                    authManager.authenticate()
                }) {
                    HStack {
                        if authManager.isLoading {
                            ProgressView()
                                .scaleEffect(0.8)
                        } else {
                            Image(systemName: "key.fill")
                        }
                        Text(authManager.isLoading ? "Authenticating..." : "Sign In with Microsoft")
                    }
                    .frame(minWidth: 200)
                    .padding()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(authManager.isLoading)
            }
        }
        .frame(maxWidth: 400)
        .padding()
    }
}

struct DeviceSearchView: View {
    @ObservedObject var apiManager: DefenderAPIManager
    @ObservedObject var authManager: DefenderAuthManager
    @Binding var deviceName: String
    @Binding var selectedDevice: DefenderDevice?
    @Binding var showingOffboardConfirmation: Bool
    @Binding var showingAlert: Bool
    @Binding var alertMessage: String
    @State private var isLoadingUsers = false
    
    var body: some View {
        VStack(spacing: 24) {
            // Search Section
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    TextField("Enter device name...", text: $deviceName)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit {
                            searchDevice()
                        }
                    
                    Button("Search") {
                        searchDevice()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(deviceName.isEmpty || apiManager.isLoading)
                    
                    if !deviceName.isEmpty || selectedDevice != nil {
                        Button("Clear Search") {
                            deviceName = ""
                            selectedDevice = nil
                        }
                        .buttonStyle(.bordered)
                    }
                }
            }
            
            // Device Information with Logon Users
            if let device = selectedDevice {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            Text("Device Information")
                                .font(.title2)
                                .fontWeight(.semibold)
                            
                            Spacer()
                            
                            Button(action: {
                                apiManager.toggleFavorite(device)
                            }) {
                                Image(systemName: apiManager.isFavorite(device) ? "heart.fill" : "heart")
                                    .foregroundColor(apiManager.isFavorite(device) ? .red : .gray)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                        
                        // Basic Device Info
                        VStack(spacing: 12) {
                            InfoRow(label: "Device ID", value: device.id)
                            InfoRow(label: "Device Name", value: device.computerDnsName)
                            InfoRow(label: "Health Status", value: device.healthStatus, statusColor: device.healthStatus == "Active" ? .green : .orange)
                            InfoRow(label: "OS Platform", value: device.osPlatform)
                            InfoRow(label: "Last Seen", value: formatDate(device.lastSeen))
                            if let aadId = device.aadDeviceId {
                                InfoRow(label: "AAD Device ID", value: aadId)
                            }
                        }
                        .padding()
                        .background(Color(.controlBackgroundColor))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        
                        // Logon Users Section
                        LogonUsersSection(
                            device: device,
                            isLoading: isLoadingUsers
                        )
                        
                        // Offboard Button
                        Button("Offboard Device") {
                            showingOffboardConfirmation = true
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .tint(.red)
                        .frame(maxWidth: .infinity)
                    }
                    .padding()
                }
            }
            
            // Load Devices Section
            if apiManager.devices.isEmpty && !apiManager.isLoading {
                VStack(spacing: 16) {
                    Image(systemName: "server.rack")
                        .font(.system(size: 50))
                        .foregroundColor(.gray)
                    
                    Text("No devices loaded")
                        .font(.headline)
                    
                    Text("Load your Defender devices to start searching")
                        .foregroundColor(.secondary)
                    
                    Button("Load Defender Devices") {
                        if let token = authManager.accessToken {
                            apiManager.fetchAllDevices(accessToken: token)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                }
            }
            
            // Error Messages
            if let errorMessage = apiManager.errorMessage {
                Text(errorMessage)
                    .foregroundColor(.red)
                    .padding()
                    .background(Color.red.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            
            Spacer()
        }
    }
    
    private func searchDevice() {
        guard !deviceName.isEmpty else { return }
        
        apiManager.addRecentSearch(deviceName)
        
        if apiManager.devices.isEmpty && !apiManager.isLoading {
            if let token = authManager.accessToken {
                apiManager.fetchAllDevices(accessToken: token)
            }
        }
        
        if let foundDevice = apiManager.searchDevice(deviceName: deviceName) {
            // Fetch device with logon users
            isLoadingUsers = true
            
            if let token = authManager.accessToken {
                apiManager.fetchDeviceWithUsers(deviceId: foundDevice.id, accessToken: token) { deviceWithUsers, error in
                    isLoadingUsers = false
                    
                    if let deviceWithUsers = deviceWithUsers {
                        selectedDevice = deviceWithUsers
                    } else {
                        selectedDevice = foundDevice // Fallback to device without users
                        if let error = error {
                            alertMessage = "Device found, but failed to load logon users: \(error)"
                            showingAlert = true
                        }
                    }
                }
            } else {
                selectedDevice = foundDevice
            }
        } else if !apiManager.devices.isEmpty {
            selectedDevice = nil
            alertMessage = "Device '\(deviceName)' not found."
            showingAlert = true
        }
    }
    
    private func formatDate(_ dateString: String) -> String {
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: dateString) {
            let displayFormatter = DateFormatter()
            displayFormatter.dateStyle = .medium
            displayFormatter.timeStyle = .short
            return displayFormatter.string(from: date)
        }
        return dateString
    }
}

struct FavoritesView: View {
    @ObservedObject var apiManager: DefenderAPIManager
    @ObservedObject var authManager: DefenderAuthManager
    @State private var selectedDevice: DefenderDevice?
    @State private var showingOffboardConfirmation = false
    @State private var showingAlert = false
    @State private var alertMessage = ""
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if apiManager.favoriteDevices.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "heart")
                        .font(.system(size: 50))
                        .foregroundColor(.gray)
                    
                    Text("No favorite devices")
                        .font(.headline)
                    
                    Text("Mark devices as favorites to quickly access them here")
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(apiManager.favoriteDevices) { device in
                            FavoriteDeviceCard(
                                device: device,
                                apiManager: apiManager,
                                authManager: authManager,
                                onOffboard: {
                                    selectedDevice = device
                                    showingOffboardConfirmation = true
                                }
                            )
                        }
                    }
                    .padding()
                }
            }
        }
        .alert("Confirm Offboard", isPresented: $showingOffboardConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Offboard", role: .destructive) {
                offboardSelectedDevice()
            }
        } message: {
            Text("Are you sure you want to offboard '\(selectedDevice?.computerDnsName ?? "")'? This action cannot be undone.")
        }
        .alert(alertMessage.contains("Success") ? "Offboard Successful" : "Offboard Failed", isPresented: $showingAlert) {
            Button("OK") { }
        } message: {
            Text(alertMessage)
        }
    }
    
    private func offboardSelectedDevice() {
        guard let device = selectedDevice,
              let token = authManager.accessToken else { return }
        
        apiManager.offboardDevice(deviceId: device.id, accessToken: token) { success, error in
            DispatchQueue.main.async {
                if success {
                    self.alertMessage = "✅ Success!\n\nDevice '\(device.computerDnsName)' has been successfully offboarded."
                    self.selectedDevice = nil
                    // Remove from favorites if it was offboarded
                    if let index = self.apiManager.favoriteDevices.firstIndex(where: { $0.id == device.id }) {
                        self.apiManager.favoriteDevices.remove(at: index)
                    }
                } else {
                    self.alertMessage = "❌ Failed to offboard device.\n\n\(error ?? "Unknown error occurred")"
                }
                self.showingAlert = true
            }
        }
    }
}

struct FavoriteDeviceCard: View {
    let device: DefenderDevice
    @ObservedObject var apiManager: DefenderAPIManager
    @ObservedObject var authManager: DefenderAuthManager
    let onOffboard: () -> Void
    @State private var isLoadingUsers = false
    @State private var deviceWithUsers: DefenderDevice?
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(device.computerDnsName)
                        .font(.headline)
                    Text(device.osPlatform)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Button(action: {
                    apiManager.toggleFavorite(device)
                }) {
                    Image(systemName: "heart.fill")
                        .foregroundColor(.red)
                }
                .buttonStyle(PlainButtonStyle())
            }
            
            HStack {
                StatusBadge(status: device.healthStatus)
                Spacer()
                Text(formatDate(device.lastSeen))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            // Device Information Section
            VStack(alignment: .leading, spacing: 8) {
                InfoRow(label: "Device ID", value: device.id)
                InfoRow(label: "Health Status", value: device.healthStatus, statusColor: device.healthStatus == "Active" ? .green : .orange)
                InfoRow(label: "Last Seen", value: formatDate(device.lastSeen))
                if let aadId = device.aadDeviceId {
                    InfoRow(label: "AAD Device ID", value: aadId)
                }
            }
            .padding(.top, 8)
            
            // Logon Users Section (compact version)
            LogonUsersCompactSection(
                device: deviceWithUsers ?? device,
                isLoading: isLoadingUsers
            )
            
            // Offboard Button
            Button("Offboard Device") {
                onOffboard()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.regular)
            .tint(.red)
            .frame(maxWidth: .infinity)
        }
        .padding()
        .background(Color(.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .shadow(color: Color.black.opacity(0.05), radius: 2, x: 0, y: 1)
        .onAppear {
            loadLogonUsers()
        }
    }
    
    private func loadLogonUsers() {
        // Load users for favorites on appear
        guard device.logonUsers.isEmpty && !isLoadingUsers else { return }
        
        isLoadingUsers = true
        if let token = authManager.accessToken {
            apiManager.fetchDeviceWithUsers(deviceId: device.id, accessToken: token) { deviceWithUsersResult, error in
                isLoadingUsers = false
                if let deviceWithUsersResult = deviceWithUsersResult {
                    deviceWithUsers = deviceWithUsersResult
                }
            }
        }
    }
    
    private func formatDate(_ dateString: String) -> String {
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: dateString) {
            let displayFormatter = DateFormatter()
            displayFormatter.dateStyle = .medium
            displayFormatter.timeStyle = .short
            return displayFormatter.string(from: date)
        }
        return dateString
    }
}

// MARK: - Recent Searches View
struct RecentSearchesView: View {
    @ObservedObject var apiManager: DefenderAPIManager
    @ObservedObject var authManager: DefenderAuthManager
    @Binding var deviceName: String
    @Binding var selectedView: SidebarSection
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if apiManager.recentSearches.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "clock")
                        .font(.system(size: 50))
                        .foregroundColor(.gray)
                    
                    Text("No recent searches")
                        .font(.headline)
                    
                    Text("Your recent device searches will appear here")
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(apiManager.recentSearches, id: \.self) { search in
                            RecentSearchCard(
                                searchTerm: search,
                                apiManager: apiManager,
                                authManager: authManager,
                                onTap: {
                                    deviceName = search
                                    selectedView = .search
                                }
                            )
                        }
                    }
                    .padding()
                }
            }
        }
    }
}

// MARK: - Recent Search Card
struct RecentSearchCard: View {
    let searchTerm: String
    @ObservedObject var apiManager: DefenderAPIManager
    @ObservedObject var authManager: DefenderAuthManager
    let onTap: () -> Void
    @State private var foundDevice: DefenderDevice?
    @State private var isLoading = false
    
    var body: some View {
        Button(action: onTap) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.blue)
                    Text(searchTerm)
                        .foregroundColor(.primary)
                        .fontWeight(.medium)
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                if let device = foundDevice {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            StatusBadge(status: device.healthStatus)
                            Spacer()
                            Text(device.osPlatform)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        // Show inline user info
                        InlineUserDisplay(
                            device: device,
                            isLoading: isLoading
                        )
                    }
                    .padding(.top, 4)
                } else if !apiManager.devices.isEmpty {
                    Text("Device not found")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .italic()
                }
            }
            .padding()
            .background(Color(.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(PlainButtonStyle())
        .onAppear {
            loadDeviceInfo()
        }
    }
    
    private func loadDeviceInfo() {
        // Find the device in the loaded devices
        if let device = apiManager.devices.first(where: { $0.computerDnsName.lowercased() == searchTerm.lowercased() }) {
            foundDevice = device
            
            // Load users if not already loaded
            if device.logonUsers.isEmpty && !device.usersLoaded && !isLoading {
                isLoading = true
                if let token = authManager.accessToken {
                    apiManager.loadUsersForDevice(deviceId: device.id, accessToken: token)
                    
                    // Watch for updates to the device
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                        if let updatedDevice = apiManager.devices.first(where: { $0.id == device.id }) {
                            foundDevice = updatedDevice
                        }
                        isLoading = false
                    }
                }
            }
        }
    }
}

// MARK: - All Devices View
struct AllDevicesView: View {
    @ObservedObject var apiManager: DefenderAPIManager
    @ObservedObject var authManager: DefenderAuthManager
    @State private var searchText = ""
    @State private var selectedPlatform = "All"
    @State private var selectedStatus = "All"
    @State private var selectedDevices: Set<String> = []
    @State private var showingBulkOffboardConfirmation = false
    @State private var showingAlert = false
    @State private var alertMessage = ""
    @State private var isProcessingBulkOffboard = false
    @Binding var selectedView: SidebarSection
    @Binding var deviceName: String
    @Binding var selectedDevice: DefenderDevice?
    
    private var filteredDevices: [DefenderDevice] {
        var filtered = apiManager.devices
        
        if !searchText.isEmpty {
            filtered = filtered.filter { device in
                device.computerDnsName.localizedCaseInsensitiveContains(searchText)
            }
        }
        
        if selectedPlatform != "All" {
            filtered = filtered.filter { $0.osPlatform == selectedPlatform }
        }
        
        if selectedStatus != "All" {
            filtered = filtered.filter { $0.healthStatus == selectedStatus }
        }
        
        return filtered
    }
    
    private var platforms: [String] {
        ["All"] + Array(Set(apiManager.devices.map { $0.osPlatform })).sorted()
    }
    
    private var statuses: [String] {
        ["All"] + Array(Set(apiManager.devices.map { $0.healthStatus })).sorted()
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Header with selection controls
            VStack(spacing: 12) {
                // Filters row
                HStack {
                    TextField("Search devices...", text: $searchText)
                        .textFieldStyle(.roundedBorder)
                    
                    Picker("Platform", selection: $selectedPlatform) {
                        ForEach(platforms, id: \.self) { platform in
                            Text(platform).tag(platform)
                        }
                    }
                    .frame(width: 150)
                    
                    Picker("Status", selection: $selectedStatus) {
                        ForEach(statuses, id: \.self) { status in
                            Text(status).tag(status)
                        }
                    }
                    .frame(width: 120)
                    
                    Button("Refresh") {
                        if let token = authManager.accessToken {
                            apiManager.fetchAllDevices(accessToken: token)
                        }
                    }
                    .disabled(apiManager.isLoading)
                }
                
                // Selection controls row
                if !filteredDevices.isEmpty {
                    HStack {
                        // Selection info and controls
                        HStack(spacing: 12) {
                            if selectedDevices.isEmpty {
                                Text("\(filteredDevices.count) devices")
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                            } else {
                                Text("\(selectedDevices.count) selected")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                    .foregroundColor(.blue)
                            }
                            
                            Button(selectedDevices.count == filteredDevices.count ? "Deselect All" : "Select All") {
                                if selectedDevices.count == filteredDevices.count {
                                    selectedDevices.removeAll()
                                } else {
                                    selectedDevices = Set(filteredDevices.map { $0.id })
                                }
                            }
                            .font(.subheadline)
                            .disabled(filteredDevices.isEmpty)
                        }
                        
                        Spacer()
                        
                        // Bulk action buttons
                        HStack(spacing: 8) {
                            if !selectedDevices.isEmpty {
                                Button("Clear Selection") {
                                    selectedDevices.removeAll()
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                
                                Button("Offboard Selected (\(selectedDevices.count))") {
                                    showingBulkOffboardConfirmation = true
                                }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.small)
                                .tint(.red)
                                .disabled(isProcessingBulkOffboard)
                            }
                        }
                    }
                    
                    Divider()
                }
            }
            .padding()
            .background(Color(.controlBackgroundColor).opacity(0.5))
            
            // Device List
            if filteredDevices.isEmpty && !apiManager.isLoading {
                VStack(spacing: 16) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 50))
                        .foregroundColor(.gray)
                    
                    Text(apiManager.devices.isEmpty ? "No devices loaded" : "No matching devices")
                        .font(.headline)
                    
                    if apiManager.devices.isEmpty {
                        Button("Load Devices") {
                            if let token = authManager.accessToken {
                                apiManager.fetchAllDevices(accessToken: token)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(filteredDevices) { device in
                            MultiSelectDeviceRow(
                                device: device,
                                apiManager: apiManager,
                                authManager: authManager,
                                isSelected: selectedDevices.contains(device.id),
                                onSelectionChanged: { isSelected in
                                    if isSelected {
                                        selectedDevices.insert(device.id)
                                    } else {
                                        selectedDevices.remove(device.id)
                                    }
                                },
                                onViewDetails: {
                                    // Navigate to Device Search with this device
                                    deviceName = device.computerDnsName
                                    selectedDevice = device
                                    selectedView = .search
                                    
                                    // Load users for the device if needed
                                    if device.logonUsers.isEmpty && !device.usersLoaded {
                                        if let token = authManager.accessToken {
                                            apiManager.fetchDeviceWithUsers(deviceId: device.id, accessToken: token) { deviceWithUsers, error in
                                                if let deviceWithUsers = deviceWithUsers {
                                                    selectedDevice = deviceWithUsers
                                                }
                                            }
                                        }
                                    }
                                }
                            )
                        }
                    }
                    .padding()
                }
            }
        }
        .alert("Confirm Bulk Offboard", isPresented: $showingBulkOffboardConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Offboard \(selectedDevices.count) Devices", role: .destructive) {
                performBulkOffboard()
            }
        } message: {
            Text("Are you sure you want to offboard \(selectedDevices.count) selected devices? This action cannot be undone.")
        }
        .alert("Bulk Offboard Result", isPresented: $showingAlert) {
            Button("OK") { }
        } message: {
            Text(alertMessage)
        }
    }
    
    private func performBulkOffboard() {
        guard !selectedDevices.isEmpty,
              let token = authManager.accessToken else { return }
        
        isProcessingBulkOffboard = true
        let devicesToOffboard = apiManager.devices.filter { selectedDevices.contains($0.id) }
        
        var successCount = 0
        var failureCount = 0
        var completedCount = 0
        let totalCount = devicesToOffboard.count
        
        for device in devicesToOffboard {
            apiManager.offboardDevice(deviceId: device.id, accessToken: token) { success, error in
                completedCount += 1
                
                if success {
                    successCount += 1
                } else {
                    failureCount += 1
                }
                
                // Check if all operations completed
                if completedCount == totalCount {
                    DispatchQueue.main.async {
                        isProcessingBulkOffboard = false
                        selectedDevices.removeAll()
                        
                        if failureCount == 0 {
                            alertMessage = "Successfully offboarded \(successCount) devices."
                        } else if successCount == 0 {
                            alertMessage = "Failed to offboard any devices. \(failureCount) failures."
                        } else {
                            alertMessage = "Offboarded \(successCount) devices successfully. \(failureCount) failed."
                        }
                        
                        showingAlert = true
                    }
                }
            }
        }
    }
}

// MARK: - Multi-Select Device Row
struct MultiSelectDeviceRow: View {
    let device: DefenderDevice
    @ObservedObject var apiManager: DefenderAPIManager
    @ObservedObject var authManager: DefenderAuthManager
    let isSelected: Bool
    let onSelectionChanged: (Bool) -> Void
    let onViewDetails: () -> Void
    
    var body: some View {
        HStack {
            // Selection checkbox
            Button(action: {
                onSelectionChanged(!isSelected)
            }) {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .foregroundColor(isSelected ? .blue : .gray)
                    .font(.system(size: 20))
            }
            .buttonStyle(PlainButtonStyle())
            
            // Device info with user info
            VStack(alignment: .leading, spacing: 4) {
                Text(device.computerDnsName)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(device.osPlatform)
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                // User info inline
                InlineUserDisplay(
                    device: device,
                    isLoading: apiManager.devicesLoadingUsers.contains(device.id)
                )
            }
            
            Spacer()
            
            // View Details button
            Button("View Details") {
                onViewDetails()
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            
            // Status badge
            StatusBadge(status: device.healthStatus)
            
            // Favorite button
            Button(action: {
                apiManager.toggleFavorite(device)
            }) {
                Image(systemName: apiManager.isFavorite(device) ? "heart.fill" : "heart")
                    .foregroundColor(apiManager.isFavorite(device) ? .red : .gray)
            }
            .buttonStyle(PlainButtonStyle())
        }
        .padding()
        .background(isSelected ? Color.blue.opacity(0.1) : Color(.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(isSelected ? Color.blue : Color.clear, lineWidth: 2)
        )
        .contentShape(Rectangle())
        .onTapGesture {
            onSelectionChanged(!isSelected)
        }
        .onAppear {
            loadUsersIfNeeded()
        }
    }
    
    private func loadUsersIfNeeded() {
        // Only load if device has no users AND we're not already loading AND users haven't been loaded before
        guard device.logonUsers.isEmpty &&
                !device.usersLoaded &&
                !apiManager.devicesLoadingUsers.contains(device.id) else { return }
        
        if let token = authManager.accessToken {
            apiManager.loadUsersForDevice(deviceId: device.id, accessToken: token)
        }
    }
}

// MARK: - Settings View
struct SettingsView: View {
    @ObservedObject var authManager: DefenderAuthManager
    @ObservedObject var apiManager: DefenderAPIManager
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Settings")
                .font(.title2)
                .fontWeight(.semibold)
            
            // Account Information
            VStack(alignment: .leading, spacing: 12) {
                Text("Account")
                    .font(.headline)
                
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Status:")
                            .fontWeight(.medium)
                        Text(authManager.isAuthenticated ? "Authenticated" : "Not Authenticated")
                            .foregroundColor(authManager.isAuthenticated ? .green : .gray)
                    }
                    
                    if authManager.isAuthenticated {
                        Button("Sign Out") {
                            authManager.signOut()
                            apiManager.devices = []
                        }
                        .buttonStyle(.bordered)
                        .tint(.red)
                    }
                }
                .padding()
                .background(Color(.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            
            // Data Management
            VStack(alignment: .leading, spacing: 12) {
                Text("Data Management")
                    .font(.headline)
                
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Loaded Devices:")
                            .fontWeight(.medium)
                        Text("\(apiManager.devices.count)")
                    }
                    
                    HStack {
                        Text("Favorite Devices:")
                            .fontWeight(.medium)
                        Text("\(apiManager.favoriteDevices.count)")
                    }
                    
                    HStack {
                        Text("Recent Searches:")
                            .fontWeight(.medium)
                        Text("\(apiManager.recentSearches.count)")
                    }
                    
                    Divider()
                    
                    HStack(spacing: 12) {
                        Button("Clear Recent Searches") {
                            apiManager.recentSearches.removeAll()
                        }
                        .buttonStyle(.bordered)
                        
                        Button("Clear Favorites") {
                            apiManager.favoriteDevices.removeAll()
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding()
                .background(Color(.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            
            Spacer()
        }
        .padding()
    }
}

// MARK: - Main App View

struct ContentView: View {
    @StateObject private var authManager = DefenderAuthManager()
    @StateObject private var apiManager = DefenderAPIManager()
    @State private var selectedView: SidebarSection = .search
    @State private var deviceName = ""
    @State private var selectedDevice: DefenderDevice?
    @State private var showingOffboardConfirmation = false
    @State private var showingAlert = false
    @State private var alertMessage = ""
    
    var body: some View {
        NavigationSplitView {
            SidebarView(
                authManager: authManager,
                apiManager: apiManager,
                selectedView: $selectedView
            )
        } detail: {
            detailView
                .alert("Confirm Offboard", isPresented: $showingOffboardConfirmation) {
                    Button("Cancel", role: .cancel) { }
                    Button("Offboard", role: .destructive) {
                        offboardSelectedDevice()
                    }
                } message: {
                    Text("Are you sure you want to offboard '\(selectedDevice?.computerDnsName ?? "")'? This action cannot be undone.")
                }
                .alert(alertMessage.contains("Success") ? "Offboard Successful" : "Offboard Failed", isPresented: $showingAlert) {
                    Button("OK") { }
                } message: {
                    Text(alertMessage)
                }
                .navigationTitle(selectedView.title)
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        if authManager.isAuthenticated {
                            Button("Sign Out") {
                                authManager.signOut()
                                apiManager.devices = []
                                selectedDevice = nil
                                deviceName = ""
                                selectedView = .search
                            }
                        }
                    }
                }
                .onAppear {
                    // Auto-load devices when authenticated
                    if authManager.isAuthenticated && apiManager.devices.isEmpty && !apiManager.isLoading {
                        if let token = authManager.accessToken {
                            apiManager.fetchAllDevices(accessToken: token)
                        }
                    }
                }
        }
        .frame(minWidth: 900, minHeight: 600)
    }
    
    @ViewBuilder
    private var detailView: some View {
        if !authManager.isAuthenticated {
            AuthenticationView(authManager: authManager)
        } else {
            switch selectedView {
            case .search:
                DeviceSearchView(
                    apiManager: apiManager,
                    authManager: authManager,
                    deviceName: $deviceName,
                    selectedDevice: $selectedDevice,
                    showingOffboardConfirmation: $showingOffboardConfirmation,
                    showingAlert: $showingAlert,
                    alertMessage: $alertMessage
                )
            case .dashboard:
                DashboardView(apiManager: apiManager, authManager: authManager)
            case .favorites:
                FavoritesView(apiManager: apiManager, authManager: authManager)
            case .recent:
                RecentSearchesView(apiManager: apiManager, authManager: authManager, deviceName: $deviceName, selectedView: $selectedView)
            case .allDevices:
                AllDevicesView(
                    apiManager: apiManager,
                    authManager: authManager,
                    selectedView: $selectedView,
                    deviceName: $deviceName,
                    selectedDevice: $selectedDevice
                )
            case .settings:
                SettingsView(authManager: authManager, apiManager: apiManager)
            }
        }
    }
    
    private func offboardSelectedDevice() {
        guard let device = selectedDevice,
              let token = authManager.accessToken else { return }
        
        apiManager.offboardDevice(deviceId: device.id, accessToken: token) { success, error in
            DispatchQueue.main.async {
                if success {
                    self.alertMessage = "✅ Success!\n\nDevice '\(device.computerDnsName)' has been successfully offboarded."
                    self.selectedDevice = nil
                    self.deviceName = ""
                } else {
                    self.alertMessage = "❌ Failed to offboard device.\n\n\(error ?? "Unknown error occurred")"
                }
                self.showingAlert = true
            }
        }
    }
}

// MARK: - App Entry Point
// Note: To make the app quit when window closes, create a separate App.swift file with:
/*
import SwiftUI

@main
struct DefenderOffboardingApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .commands {
            CommandGroup(replacing: .newItem) { }
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}
*/
// MARK: - SwiftUI Previews

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
