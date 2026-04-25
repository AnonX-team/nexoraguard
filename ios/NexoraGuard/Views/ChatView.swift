import SwiftUI

struct ChatView: View {

    @State private var messages: [ChatBubble] = []
    @State private var history: [ChatHistoryMessage] = []
    @State private var inputText = ""
    @State private var isThinking = false
    @State private var agentStatus = "Ready"
    @State private var agentStatusColor = Color.riskLow

    private let quickPrompts = [
        "What threats are active?",
        "Explain the risk score",
        "How to reduce risk?",
        "Show suspicious processes",
        "Is my system safe?"
    ]

    var body: some View {
        NavigationView {
            ZStack {
                Color.bgDark.ignoresSafeArea()

                VStack(spacing: 0) {
                    // ── Header ────────────────────────────────────────────
                    headerBar

                    // ── Messages ──────────────────────────────────────────
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 12) {
                                ForEach(messages) { msg in
                                    ChatBubbleView(bubble: msg)
                                        .id(msg.id)
                                }
                                if isThinking {
                                    typingIndicator
                                }
                            }
                            .padding(12)
                        }
                        .onChange(of: messages.count) { _ in
                            if let last = messages.last {
                                withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                            }
                        }
                    }

                    // ── Quick prompts ─────────────────────────────────────
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(quickPrompts, id: \.self) { prompt in
                                Button(prompt) {
                                    inputText = prompt
                                    send()
                                }
                                .font(.system(size: 12))
                                .foregroundColor(.accentCyan)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(Color.bgCard)
                                .cornerRadius(16)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                    }

                    // ── Input bar ─────────────────────────────────────────
                    inputBar
                }
            }
            .navigationBarHidden(true)
        }
        .onAppear(perform: showWelcome)
    }

    // MARK: - Subviews

    private var headerBar: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("AI SECURITY AGENT")
                    .font(.system(size: 14, weight: .bold, design: .monospaced))
                    .foregroundColor(.accentCyan)
                    .kerning(1)
                Text(agentStatus)
                    .font(.system(size: 11))
                    .foregroundColor(agentStatusColor)
            }
            Spacer()
            Button("Clear") {
                messages.removeAll()
                history.removeAll()
                showWelcome()
            }
            .font(.system(size: 13))
            .foregroundColor(.textSecondary)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color.bgCard)
    }

    private var typingIndicator: some View {
        HStack(spacing: 8) {
            ProgressView()
                .progressViewStyle(CircularProgressViewStyle(tint: .accentCyan))
                .scaleEffect(0.7)
            Text("Agent is thinking...")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.textSecondary)
        }
    }

    private var inputBar: some View {
        HStack(spacing: 10) {
            TextField("Ask about threats...", text: $inputText, axis: .vertical)
                .lineLimit(1...4)
                .font(.system(size: 14, design: .monospaced))
                .foregroundColor(.textPrimary)
                .padding(12)
                .background(Color.bgCard2)
                .cornerRadius(10)
                .onSubmit { send() }

            Button(action: send) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 36))
                    .foregroundColor(inputText.trimmingCharacters(in: .whitespaces).isEmpty
                                     ? .textSecondary : .accentCyan)
            }
            .disabled(inputText.trimmingCharacters(in: .whitespaces).isEmpty || isThinking)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Color.bgCard)
    }

    // MARK: - Actions

    private func showWelcome() {
        if messages.isEmpty {
            messages.append(ChatBubble(
                sender: .agent,
                text: "Hello! I'm NexoraGuard AI. Ask me anything about your system security — threats, processes, network connections, or remediation steps.",
                time: nowTime()
            ))
        }
    }

    private func send() {
        let text = inputText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        inputText = ""

        messages.append(ChatBubble(sender: .user, text: text, time: nowTime()))
        history.append(ChatHistoryMessage(role: "user", content: text))

        isThinking = true
        agentStatus = "Thinking..."
        agentStatusColor = .riskMedium

        let recentHistory = Array(history.dropLast().suffix(10))

        APIService.shared.chat(message: text, history: recentHistory) { result in
            DispatchQueue.main.async {
                isThinking = false
                switch result {
                case .success(let resp):
                    let reply = resp.response ?? "Sorry, I couldn't process that request."
                    history.append(ChatHistoryMessage(role: "assistant", content: reply))
                    messages.append(ChatBubble(sender: .agent, text: reply, time: nowTime()))
                    agentStatus = "Ready"
                    agentStatusColor = .riskLow
                case .failure(let err):
                    messages.append(ChatBubble(
                        sender: .agent,
                        text: "Connection error: \(err.localizedDescription)",
                        time: nowTime()
                    ))
                    agentStatus = "Error"
                    agentStatusColor = .riskCritical
                }
            }
        }
    }

    private func nowTime() -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f.string(from: Date())
    }
}

// MARK: - Chat bubble view

struct ChatBubbleView: View {
    let bubble: ChatBubble

    var isUser: Bool { bubble.sender == .user }

    var body: some View {
        VStack(alignment: isUser ? .trailing : .leading, spacing: 3) {
            Text(isUser ? "YOU" : "NEXORA AI")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .kerning(0.5)
                .foregroundColor(isUser ? .accentCyan : .textSecondary)
                .frame(maxWidth: .infinity, alignment: isUser ? .trailing : .leading)

            HStack {
                if isUser { Spacer(minLength: 60) }

                Text(bubble.text)
                    .font(.system(size: 14))
                    .foregroundColor(.textPrimary)
                    .padding(12)
                    .background(isUser ? Color(hex: "#00B0CC") : Color.bgCard)
                    .cornerRadius(12)
                    .multilineTextAlignment(.leading)

                if !isUser { Spacer(minLength: 60) }
            }

            Text(bubble.time)
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.textSecondary)
                .frame(maxWidth: .infinity, alignment: isUser ? .trailing : .leading)
        }
    }
}
