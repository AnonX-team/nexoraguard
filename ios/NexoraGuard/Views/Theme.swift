import SwiftUI

// MARK: - App Colors (no asset catalog needed)

extension Color {
    static let bgDark        = Color(hex: "#0D0D0D")
    static let bgCard        = Color(hex: "#1A1A2E")
    static let bgCard2       = Color(hex: "#111111")
    static let accentCyan    = Color(hex: "#00E5FF")
    static let textPrimary   = Color.white
    static let textSecondary = Color(hex: "#888888")
    static let divider       = Color(hex: "#2A2A2A")
    static let riskCritical  = Color(hex: "#D32F2F")
    static let riskHigh      = Color(hex: "#F57C00")
    static let riskMedium    = Color(hex: "#F9A825")
    static let riskLow       = Color(hex: "#388E3C")
    static let riskUnknown   = Color(hex: "#1976D2")

    init(hex: String) {
        let h = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: h).scanHexInt64(&int)
        let r = Double((int >> 16) & 0xFF) / 255
        let g = Double((int >>  8) & 0xFF) / 255
        let b = Double( int        & 0xFF) / 255
        self.init(red: r, green: g, blue: b)
    }

    static func riskColor(for risk: String?) -> Color {
        switch risk {
        case "CRITICAL": return .riskCritical
        case "HIGH":     return .riskHigh
        case "MEDIUM":   return .riskMedium
        case "LOW":      return .riskLow
        default:         return .riskUnknown
        }
    }
}

// MARK: - Reusable stat card

struct StatCard: View {
    let label: String
    let value: String
    var subtitle: String? = nil
    var valueColor: Color = .accentCyan

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundColor(.textSecondary)
                .kerning(1)

            Text(value)
                .font(.system(size: 20, weight: .bold, design: .monospaced))
                .foregroundColor(valueColor)

            if let sub = subtitle {
                Text(sub)
                    .font(.system(size: 10))
                    .foregroundColor(.textSecondary)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.bgCard)
        .cornerRadius(12)
    }
}

// MARK: - Section header

struct SectionHeader: View {
    let title: String
    var body: some View {
        Text(title)
            .font(.system(size: 10, weight: .bold, design: .monospaced))
            .kerning(1.5)
            .foregroundColor(.textSecondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 8)
    }
}

// MARK: - Risk badge

struct RiskBadge: View {
    let risk: String?
    var body: some View {
        Text(risk ?? "UNKNOWN")
            .font(.system(size: 9, weight: .bold))
            .kerning(0.5)
            .foregroundColor(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(Color.riskColor(for: risk))
            .cornerRadius(3)
    }
}
