package com.nexora.securityagent;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import androidx.annotation.Nullable;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

/**
 * Background service that polls /status and fires a notification
 * whenever the risk level is HIGH or CRITICAL.
 *
 * Started by MainActivity, stopped when app is fully closed.
 */
public class ThreatPollingService extends Service {

    private Handler handler;
    private Runnable pollRunnable;
    private AppPrefs prefs;
    private String lastNotifiedRisk = "";

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = new AppPrefs(this);
        handler = new Handler(Looper.getMainLooper());
        NotificationHelper.createChannel(this);
        startPolling();
    }

    private void startPolling() {
        pollRunnable = new Runnable() {
            @Override
            public void run() {
                poll();
                int intervalMs = prefs.getPollIntervalSeconds() * 1000;
                handler.postDelayed(this, intervalMs);
            }
        };
        handler.post(pollRunnable);
    }

    private void poll() {
        if (!prefs.areNotificationsEnabled()) return;

        ApiService api = RetrofitClient.get(prefs.getServerUrl());
        api.getStatus().enqueue(new Callback<StatusResponse>() {
            @Override
            public void onResponse(Call<StatusResponse> call, Response<StatusResponse> response) {
                if (!response.isSuccessful() || response.body() == null) return;

                StatusResponse status = response.body();
                String risk = status.overall_risk;
                if (risk == null) return;

                // Only notify once per consecutive HIGH/CRITICAL event
                boolean isSerious = "CRITICAL".equals(risk) || "HIGH".equals(risk);
                if (isSerious && !risk.equals(lastNotifiedRisk)) {
                    // Build summary from status
                    String summary = status.rule_alert_count + " rules triggered. "
                            + status.suspicious_process_count + " suspicious processes, "
                            + status.suspicious_connection_count + " suspicious connections.";
                    NotificationHelper.postThreatAlert(
                            ThreatPollingService.this, risk, summary);
                    lastNotifiedRisk = risk;
                } else if (!isSerious) {
                    lastNotifiedRisk = ""; // reset so next spike notifies again
                }
            }

            @Override
            public void onFailure(Call<StatusResponse> call, Throwable t) {
                // Silently ignore — server may be temporarily unreachable
            }
        });
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (handler != null && pollRunnable != null) {
            handler.removeCallbacks(pollRunnable);
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
