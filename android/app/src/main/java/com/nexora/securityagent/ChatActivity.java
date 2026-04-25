package com.nexora.securityagent;

import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class ChatActivity extends AppCompatActivity {

    private ApiService api;
    private AppPrefs prefs;

    private RecyclerView recyclerChat;
    private TextInputEditText etMessage;
    private MaterialButton btnSend;
    private LinearLayout layoutTyping;
    private LinearLayout layoutQuickPrompts;
    private TextView tvAgentStatus;

    private ChatAdapter adapter;
    private final List<ChatMessage> history = new ArrayList<>();

    private static final String[] QUICK_PROMPTS = {
            "What threats are active?",
            "Explain the risk score",
            "How to reduce risk?",
            "Show suspicious processes",
            "Is my system safe?"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);

        prefs = new AppPrefs(this);
        api = RetrofitClient.get(prefs.getServerUrl());

        recyclerChat     = findViewById(R.id.recycler_chat);
        etMessage        = findViewById(R.id.et_message);
        btnSend          = findViewById(R.id.btn_send);
        layoutTyping     = findViewById(R.id.layout_typing);
        layoutQuickPrompts = findViewById(R.id.layout_quick_prompts);
        tvAgentStatus    = findViewById(R.id.tv_agent_status);

        adapter = new ChatAdapter(new ArrayList<>());
        recyclerChat.setAdapter(adapter);
        recyclerChat.setLayoutManager(new LinearLayoutManager(this));

        btnSend.setOnClickListener(v -> sendMessage());
        etMessage.setOnEditorActionListener((v, actionId, event) -> {
            sendMessage();
            return true;
        });

        TextView clearBtn = findViewById(R.id.btn_clear_chat);
        clearBtn.setOnClickListener(v -> {
            adapter.clear();
            history.clear();
        });

        buildQuickPrompts();

        // Welcome message
        adapter.addMessage(new ChatBubble("agent",
                "Hello! I'm NexoraGuard AI. Ask me anything about your system security — "
                + "threats, processes, network connections, or remediation steps.", now()));
    }

    private void sendMessage() {
        String text = etMessage.getText() != null ? etMessage.getText().toString().trim() : "";
        if (text.isEmpty()) return;

        etMessage.setText("");
        adapter.addMessage(new ChatBubble("user", text, now()));
        recyclerChat.scrollToPosition(adapter.getItemCount() - 1);

        history.add(new ChatMessage("user", text));
        showTyping(true);
        tvAgentStatus.setText("Thinking...");
        tvAgentStatus.setTextColor(Color.parseColor("#FBC02D"));

        // Send only last 10 messages to keep payload small
        List<ChatMessage> recentHistory = history.size() > 10
                ? history.subList(history.size() - 10, history.size() - 1)
                : history.subList(0, history.size() - 1);

        api.chat(new ChatRequest(text, recentHistory)).enqueue(new Callback<ChatResponse>() {
            @Override
            public void onResponse(Call<ChatResponse> call, Response<ChatResponse> response) {
                runOnUiThread(() -> {
                    showTyping(false);
                    tvAgentStatus.setText("Ready");
                    tvAgentStatus.setTextColor(Color.parseColor("#4CAF50"));

                    String reply = (response.isSuccessful() && response.body() != null
                            && response.body().response != null)
                            ? response.body().response
                            : "Sorry, I couldn't process that request. Please try again.";

                    history.add(new ChatMessage("assistant", reply));
                    adapter.addMessage(new ChatBubble("agent", reply, now()));
                    recyclerChat.scrollToPosition(adapter.getItemCount() - 1);
                });
            }

            @Override
            public void onFailure(Call<ChatResponse> call, Throwable t) {
                runOnUiThread(() -> {
                    showTyping(false);
                    tvAgentStatus.setText("Error");
                    tvAgentStatus.setTextColor(Color.parseColor("#D32F2F"));
                    adapter.addMessage(new ChatBubble("agent",
                            "Connection error: " + t.getMessage(), now()));
                    recyclerChat.scrollToPosition(adapter.getItemCount() - 1);
                });
            }
        });
    }

    private void buildQuickPrompts() {
        for (String prompt : QUICK_PROMPTS) {
            TextView chip = new TextView(this);
            chip.setText(prompt);
            chip.setTextColor(Color.parseColor("#00E5FF"));
            chip.setTextSize(12f);
            chip.setBackground(getDrawable(android.R.drawable.dialog_frame));
            chip.setBackgroundColor(Color.parseColor("#1A1A2E"));
            chip.setPadding(20, 8, 20, 8);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.setMarginEnd(8);
            chip.setLayoutParams(lp);
            chip.setOnClickListener(v -> {
                etMessage.setText(prompt);
                sendMessage();
            });
            layoutQuickPrompts.addView(chip);
        }
    }

    private void showTyping(boolean show) {
        layoutTyping.setVisibility(show ? View.VISIBLE : View.GONE);
    }

    private String now() {
        return new SimpleDateFormat("HH:mm", Locale.getDefault()).format(new Date());
    }

    @Override
    protected void onResume() {
        super.onResume();
        api = RetrofitClient.get(prefs.getServerUrl());
    }

    // ── Chat bubble model ─────────────────────────────────────────────────────

    static class ChatBubble {
        final String sender; // "user" or "agent"
        final String text;
        final String time;

        ChatBubble(String sender, String text, String time) {
            this.sender = sender;
            this.text   = text;
            this.time   = time;
        }
    }

    // ── RecyclerView Adapter ──────────────────────────────────────────────────

    static class ChatAdapter extends RecyclerView.Adapter<ChatAdapter.VH> {

        private final List<ChatBubble> items;

        ChatAdapter(List<ChatBubble> items) {
            this.items = items;
        }

        void addMessage(ChatBubble bubble) {
            items.add(bubble);
            notifyItemInserted(items.size() - 1);
        }

        void clear() {
            items.clear();
            notifyDataSetChanged();
        }

        @Override
        public VH onCreateViewHolder(ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_chat_message, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(VH h, int position) {
            ChatBubble b = items.get(position);
            boolean isUser = "user".equals(b.sender);

            h.tvSender.setText(isUser ? "YOU" : "NEXORA AI");
            h.tvSender.setTextColor(isUser
                    ? Color.parseColor("#00E5FF") : Color.parseColor("#888888"));

            h.tvMessage.setText(b.text);
            h.tvTime.setText(b.time);

            // Align user messages to the right
            h.itemView.setLayoutParams(makeLayoutParams(isUser));
            ((LinearLayout) h.itemView).setGravity(isUser ? Gravity.END : Gravity.START);

            h.tvSender.setGravity(isUser ? Gravity.END : Gravity.START);
            h.tvTime.setGravity(isUser ? Gravity.END : Gravity.START);

            int bgColor = isUser
                    ? Color.parseColor("#00B0CC")
                    : Color.parseColor("#1A1A2E");
            h.cardMessage.setCardBackgroundColor(bgColor);
        }

        private LinearLayout.LayoutParams makeLayoutParams(boolean isUser) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            return lp;
        }

        @Override
        public int getItemCount() {
            return items.size();
        }

        static class VH extends RecyclerView.ViewHolder {
            TextView tvSender, tvMessage, tvTime;
            androidx.cardview.widget.CardView cardMessage;

            VH(View v) {
                super(v);
                tvSender  = v.findViewById(R.id.tv_sender);
                tvMessage = v.findViewById(R.id.tv_message);
                tvTime    = v.findViewById(R.id.tv_time);
                cardMessage = v.findViewById(R.id.card_message);
            }
        }
    }
}
