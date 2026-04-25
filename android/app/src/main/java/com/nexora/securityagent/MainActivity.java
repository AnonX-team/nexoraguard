package com.nexora.securityagent;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class MainActivity extends AppCompatActivity {

    private static final int REQ_NOTIF_PERMISSION = 1;
    private static final int REFRESH_INTERVAL_MS = 15_000;

    private ApiService api;
    private AppPrefs prefs;
    private Handler handler = new Handler();

    // Views
    private TextView tvRiskLevel, tvRiskScore, tvHostname, tvStatus;
    private TextView tvCpu, tvRam, tvDisk;
    private TextView tvAlertCount, tvLastScan;
    private TextView tvTotalProcesses, tvSuspiciousProcesses;
    private TextView tvTotalConnections, tvSuspiciousConnections;
    private TextView tvConnectionStatus;
    private View dotConnection;
    private CardView cardRisk;
    private ProgressBar progressRisk;
    private MaterialButton btnScan;
    private LinearLayout layoutAlerts;
    private SwipeRefreshLayout swipeRefresh;
    private BottomNavigationView bottomNav;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = new AppPrefs(this);
        api = RetrofitClient.get(prefs.getServerUrl());

        initViews();
        requestNotificationPermission();
        startThreatPollingService();
        setupBottomNav();
        setupSwipeRefresh();

        btnScan.setOnClickListener(v -> triggerManualScan());

        startAutoRefresh();
    }

    private void initViews() {
        tvRiskLevel          = findViewById(R.id.tv_risk_level);
        tvRiskScore          = findViewById(R.id.tv_risk_score);
        tvHostname           = findViewById(R.id.tv_hostname);
        tvStatus             = findViewById(R.id.tv_status);
        tvCpu                = findViewById(R.id.tv_cpu);
        tvRam                = findViewById(R.id.tv_ram);
        tvDisk               = findViewById(R.id.tv_disk);
        tvAlertCount         = findViewById(R.id.tv_alert_count);
        tvLastScan           = findViewById(R.id.tv_last_scan);
        tvTotalProcesses     = findViewById(R.id.tv_total_processes);
        tvSuspiciousProcesses= findViewById(R.id.tv_suspicious_processes);
        tvTotalConnections   = findViewById(R.id.tv_total_connections);
        tvSuspiciousConnections = findViewById(R.id.tv_suspicious_connections);
        tvConnectionStatus   = findViewById(R.id.tv_connection_status);
        dotConnection        = findViewById(R.id.dot_connection);
        cardRisk             = findViewById(R.id.card_risk);
        progressRisk         = findViewById(R.id.progress_risk);
        btnScan              = findViewById(R.id.btn_scan);
        layoutAlerts         = findViewById(R.id.layout_alerts);
        swipeRefresh         = findViewById(R.id.swipe_refresh);
        bottomNav            = findViewById(R.id.bottom_nav);
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_dashboard);
        bottomNav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            if (id == R.id.nav_dashboard) {
                return true; // already here
            } else if (id == R.id.nav_chat) {
                startActivity(new Intent(this, ChatActivity.class));
                overridePendingTransition(0, 0);
                return true;
            } else if (id == R.id.nav_alerts) {
                startActivity(new Intent(this, AlertsActivity.class));
                overridePendingTransition(0, 0);
                return true;
            } else if (id == R.id.nav_network) {
                startActivity(new Intent(this, NetworkActivity.class));
                overridePendingTransition(0, 0);
                return true;
            } else if (id == R.id.nav_settings) {
                startActivity(new Intent(this, SettingsActivity.class));
                overridePendingTransition(0, 0);
                return true;
            }
            return false;
        });
    }

    private void setupSwipeRefresh() {
        swipeRefresh.setColorSchemeColors(Color.parseColor("#00E5FF"));
        swipeRefresh.setProgressBackgroundColorSchemeColor(Color.parseColor("#1A1A2E"));
        swipeRefresh.setOnRefreshListener(() -> {
            fetchStatus();
            loadRecentAlerts();
        });
    }

    private void startAutoRefresh() {
        handler.post(refreshRunnable);
    }

    private final Runnable refreshRunnable = new Runnable() {
        @Override
        public void run() {
            fetchStatus();
            loadRecentAlerts();
            handler.postDelayed(this, REFRESH_INTERVAL_MS);
        }
    };

    private void fetchStatus() {
        api.getStatus().enqueue(new Callback<StatusResponse>() {
            @Override
            public void onResponse(Call<StatusResponse> call, Response<StatusResponse> response) {
                swipeRefresh.setRefreshing(false);
                if (response.isSuccessful() && response.body() != null) {
                    updateUI(response.body());
                    setConnected(true);
                } else {
                    setConnected(false);
                }
            }

            @Override
            public void onFailure(Call<StatusResponse> call, Throwable t) {
                swipeRefresh.setRefreshing(false);
                setConnected(false);
                tvStatus.setText("Cannot connect: " + t.getMessage());
                tvStatus.setTextColor(Color.RED);
            }
        });
    }

    private void setConnected(boolean connected) {
        runOnUiThread(() -> {
            dotConnection.setBackgroundColor(
                    connected ? Color.parseColor("#4CAF50") : Color.parseColor("#D32F2F"));
            tvConnectionStatus.setText(connected ? "Live" : "Offline");
            tvConnectionStatus.setTextColor(
                    connected ? Color.parseColor("#4CAF50") : Color.parseColor("#D32F2F"));
        });
    }

    private void updateUI(StatusResponse status) {
        runOnUiThread(() -> {
            String risk = status.overall_risk != null ? status.overall_risk : "UNKNOWN";
            int score   = status.risk_score;

            tvRiskLevel.setText(risk);
            tvRiskScore.setText(score + "/100");
            tvHostname.setText(status.hostname != null ? status.hostname : "Unknown host");
            progressRisk.setProgress(score);

            // Last scan time
            if (status.timestamp != null && status.timestamp.length() >= 19) {
                tvLastScan.setText("Last: " + status.timestamp.substring(11, 19));
            }

            tvAlertCount.setText(status.rule_alert_count + " rules triggered");

            // Attack status
            if (status.is_attack) {
                tvStatus.setText("ATTACK DETECTED");
                tvStatus.setTextColor(Color.parseColor("#D32F2F"));
            } else {
                tvStatus.setText("System Monitored");
                tvStatus.setTextColor(Color.parseColor("#4CAF50"));
            }

            // Risk card color
            int cardColor = riskColor(risk);
            cardRisk.setCardBackgroundColor(cardColor);

            // System stats
            if (status.system_stats != null) {
                tvCpu.setText(formatPercent(status.system_stats.cpu_percent));
                tvRam.setText(formatPercent(status.system_stats.ram_percent));
                tvDisk.setText(formatPercent(status.system_stats.disk_percent));
            }

            // Process & connection counts
            tvTotalProcesses.setText(String.valueOf(status.total_processes));
            tvSuspiciousProcesses.setText(status.suspicious_process_count + " suspicious");
            tvSuspiciousProcesses.setTextColor(
                    status.suspicious_process_count > 0
                            ? Color.parseColor("#F57C00") : Color.parseColor("#4CAF50"));

            tvTotalConnections.setText(String.valueOf(status.total_connections));
            tvSuspiciousConnections.setText(status.suspicious_connection_count + " suspicious");
            tvSuspiciousConnections.setTextColor(
                    status.suspicious_connection_count > 0
                            ? Color.parseColor("#F57C00") : Color.parseColor("#4CAF50"));
        });
    }

    private void loadRecentAlerts() {
        api.getAlerts(5).enqueue(new Callback<AlertsResponse>() {
            @Override
            public void onResponse(Call<AlertsResponse> call, Response<AlertsResponse> response) {
                if (!response.isSuccessful() || response.body() == null) return;
                runOnUiThread(() -> {
                    layoutAlerts.removeAllViews();
                    if (response.body().alerts == null || response.body().alerts.isEmpty()) {
                        addAlertRow("No recent alerts — system clean", "#4CAF50");
                        return;
                    }
                    for (AlertsResponse.Alert alert : response.body().alerts) {
                        String color = riskHex(alert.risk);
                        String time  = alert.timestamp != null && alert.timestamp.length() >= 19
                                ? alert.timestamp.substring(11, 19) : "";
                        String text  = "[" + alert.risk + "] " + (alert.ai_summary != null
                                ? alert.ai_summary : "Alert") + (time.isEmpty() ? "" : "  " + time);
                        addAlertRow(text, color);
                    }
                });
            }

            @Override
            public void onFailure(Call<AlertsResponse> call, Throwable t) { /* ignore */ }
        });
    }

    private void triggerManualScan() {
        tvStatus.setText("Scanning...");
        btnScan.setEnabled(false);

        api.triggerScan().enqueue(new Callback<AnalysisResponse>() {
            @Override
            public void onResponse(Call<AnalysisResponse> call, Response<AnalysisResponse> response) {
                runOnUiThread(() -> {
                    btnScan.setEnabled(true);
                    if (response.isSuccessful()) {
                        Toast.makeText(MainActivity.this, "Scan complete!", Toast.LENGTH_SHORT).show();
                        fetchStatus();
                        loadRecentAlerts();
                    }
                });
            }

            @Override
            public void onFailure(Call<AnalysisResponse> call, Throwable t) {
                runOnUiThread(() -> {
                    btnScan.setEnabled(true);
                    Toast.makeText(MainActivity.this,
                            "Scan failed: " + t.getMessage(), Toast.LENGTH_SHORT).show();
                });
            }
        });
    }

    private void addAlertRow(String text, String hexColor) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(Color.parseColor(hexColor));
        tv.setPadding(20, 14, 20, 14);
        tv.setTextSize(12f);
        layoutAlerts.addView(tv);

        View divider = new View(this);
        divider.setBackgroundColor(Color.parseColor("#2A2A2A"));
        divider.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 1));
        layoutAlerts.addView(divider);
    }

    private void startThreatPollingService() {
        Intent serviceIntent = new Intent(this, ThreatPollingService.class);
        startService(serviceIntent);
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.POST_NOTIFICATIONS},
                        REQ_NOTIF_PERMISSION);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static int riskColor(String risk) {
        if (risk == null) return Color.parseColor("#1976D2");
        switch (risk) {
            case "CRITICAL": return Color.parseColor("#D32F2F");
            case "HIGH":     return Color.parseColor("#F57C00");
            case "MEDIUM":   return Color.parseColor("#F9A825");
            case "LOW":      return Color.parseColor("#388E3C");
            default:         return Color.parseColor("#1976D2");
        }
    }

    static String riskHex(String risk) {
        if (risk == null) return "#1976D2";
        switch (risk) {
            case "CRITICAL": return "#D32F2F";
            case "HIGH":     return "#F57C00";
            case "MEDIUM":   return "#FBC02D";
            case "LOW":      return "#4CAF50";
            default:         return "#1976D2";
        }
    }

    private String formatPercent(double value) {
        return String.format(Locale.US, "%.1f%%", value);
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Re-init API in case URL changed in Settings
        api = RetrofitClient.get(prefs.getServerUrl());
        bottomNav.setSelectedItemId(R.id.nav_dashboard);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        handler.removeCallbacks(refreshRunnable);
    }
}
