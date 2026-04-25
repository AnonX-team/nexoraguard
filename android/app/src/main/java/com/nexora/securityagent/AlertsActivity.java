package com.nexora.securityagent;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import java.util.ArrayList;
import java.util.List;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class AlertsActivity extends AppCompatActivity {

    private ApiService api;
    private AppPrefs prefs;
    private RecyclerView recyclerAlerts;
    private SwipeRefreshLayout swipeRefresh;
    private TextView tvAlertBadge;
    private LinearLayout layoutFilters;

    private AlertsAdapter adapter;
    private List<AlertsResponse.Alert> allAlerts = new ArrayList<>();
    private String activeFilter = "ALL";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_alerts);

        prefs = new AppPrefs(this);
        api = RetrofitClient.get(prefs.getServerUrl());

        recyclerAlerts = findViewById(R.id.recycler_alerts);
        swipeRefresh   = findViewById(R.id.swipe_refresh);
        tvAlertBadge   = findViewById(R.id.tv_alert_badge);
        layoutFilters  = findViewById(R.id.layout_filters);

        adapter = new AlertsAdapter(new ArrayList<>());
        recyclerAlerts.setAdapter(adapter);
        recyclerAlerts.setLayoutManager(new LinearLayoutManager(this));

        buildFilterChips();

        swipeRefresh.setColorSchemeColors(Color.parseColor("#00E5FF"));
        swipeRefresh.setProgressBackgroundColorSchemeColor(Color.parseColor("#1A1A2E"));
        swipeRefresh.setOnRefreshListener(this::loadAlerts);

        setupBottomNav();
        loadAlerts();
    }

    private void buildFilterChips() {
        String[] filters = {"ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"};
        for (String f : filters) {
            TextView chip = new TextView(this);
            chip.setText(f);
            chip.setTextSize(11f);
            chip.setTypeface(null, android.graphics.Typeface.BOLD);
            chip.setPadding(20, 8, 20, 8);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.setMarginEnd(8);
            chip.setLayoutParams(lp);
            updateChipStyle(chip, f.equals(activeFilter));

            chip.setOnClickListener(v -> {
                activeFilter = f;
                for (int i = 0; i < layoutFilters.getChildCount(); i++) {
                    View child = layoutFilters.getChildAt(i);
                    if (child instanceof TextView) {
                        String tag = (String) child.getTag();
                        updateChipStyle((TextView) child, f.equals(tag));
                    }
                }
                applyFilter();
            });
            chip.setTag(f);
            layoutFilters.addView(chip);
        }
    }

    private void updateChipStyle(TextView chip, boolean selected) {
        if (selected) {
            chip.setBackgroundColor(Color.parseColor("#00E5FF"));
            chip.setTextColor(Color.parseColor("#0D0D0D"));
        } else {
            chip.setBackgroundColor(Color.parseColor("#1A1A2E"));
            chip.setTextColor(Color.parseColor("#888888"));
        }
    }

    private void loadAlerts() {
        swipeRefresh.setRefreshing(true);
        api.getAlerts(50).enqueue(new Callback<AlertsResponse>() {
            @Override
            public void onResponse(Call<AlertsResponse> call, Response<AlertsResponse> response) {
                swipeRefresh.setRefreshing(false);
                if (!response.isSuccessful() || response.body() == null) return;
                allAlerts = response.body().alerts != null
                        ? response.body().alerts : new ArrayList<>();
                runOnUiThread(() -> {
                    tvAlertBadge.setText(String.valueOf(allAlerts.size()));
                    applyFilter();
                });
            }

            @Override
            public void onFailure(Call<AlertsResponse> call, Throwable t) {
                swipeRefresh.setRefreshing(false);
            }
        });
    }

    private void applyFilter() {
        List<AlertsResponse.Alert> filtered = new ArrayList<>();
        for (AlertsResponse.Alert a : allAlerts) {
            if ("ALL".equals(activeFilter) || activeFilter.equals(a.risk)) {
                filtered.add(a);
            }
        }
        adapter.update(filtered);
    }

    @Override
    protected void onResume() {
        super.onResume();
        api = RetrofitClient.get(prefs.getServerUrl());
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        startActivity(new Intent(this, MainActivity.class));
        overridePendingTransition(0, 0);
    }

    // ── Adapter ───────────────────────────────────────────────────────────────

    static class AlertsAdapter extends RecyclerView.Adapter<AlertsAdapter.VH> {

        private List<AlertsResponse.Alert> items;

        AlertsAdapter(List<AlertsResponse.Alert> items) {
            this.items = items;
        }

        void update(List<AlertsResponse.Alert> newItems) {
            this.items = newItems;
            notifyDataSetChanged();
        }

        @Override
        public VH onCreateViewHolder(ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_alert, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(VH h, int position) {
            AlertsResponse.Alert a = items.get(position);

            String risk = a.risk != null ? a.risk : "UNKNOWN";
            int color = Color.parseColor(MainActivity.riskHex(risk));

            h.viewSeverity.setBackgroundColor(color);
            h.tvRiskBadge.setText(risk);
            h.tvRiskBadge.setBackgroundColor(color);

            String time = a.timestamp != null && a.timestamp.length() >= 19
                    ? a.timestamp.substring(0, 19).replace("T", " ") : "";
            h.tvAlertTime.setText(time);

            h.tvAlertSummary.setText(a.ai_summary != null ? a.ai_summary : "No summary");
            h.tvAlertScore.setText("Score: " + a.score + "/100 | Rules: " + a.rule_count);
        }

        @Override
        public int getItemCount() {
            return items.size();
        }

        static class VH extends RecyclerView.ViewHolder {
            View viewSeverity;
            TextView tvRiskBadge, tvAlertTime, tvAlertSummary, tvAlertScore;

            VH(View v) {
                super(v);
                viewSeverity   = v.findViewById(R.id.view_severity);
                tvRiskBadge    = v.findViewById(R.id.tv_risk_badge);
                tvAlertTime    = v.findViewById(R.id.tv_alert_time);
                tvAlertSummary = v.findViewById(R.id.tv_alert_summary);
                tvAlertScore   = v.findViewById(R.id.tv_alert_score);
            }
        }
    }
}
