//
//  Defender_Offboarding_ManagerApp.swift
//  Defender Offboarding Manager
//
//  Created by Eddie Jimenez on 8/6/25.
//

import SwiftUI

@main
struct Aya_OffboarderApp: App {
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

