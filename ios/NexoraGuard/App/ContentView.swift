import SwiftUI

struct ContentView: View {
    var body: some View {
        TabView {
            DashboardView()
                .tabItem {
                    Label("Dashboard", systemImage: "shield.fill")
                }

            ChatView()
                .tabItem {
                    Label("AI Chat", systemImage: "bubble.left.and.bubble.right.fill")
                }

            AlertsView()
                .tabItem {
                    Label("Alerts", systemImage: "exclamationmark.triangle.fill")
                }

            NetworkView()
                .tabItem {
                    Label("Network", systemImage: "network")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
        }
        .accentColor(Color("AccentCyan"))
        .onAppear {
            // Dark tab bar
            let appearance = UITabBarAppearance()
            appearance.backgroundColor = UIColor(red: 0.1, green: 0.1, blue: 0.18, alpha: 1)
            UITabBar.appearance().standardAppearance  = appearance
            UITabBar.appearance().scrollEdgeAppearance = appearance
        }
    }
}
