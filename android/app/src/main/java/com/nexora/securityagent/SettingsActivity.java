package com.nexora.securityagent;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class SettingsActivity extends AppCompatActivity {

    private AppPrefs prefs;
    private ApiService api;

    private TextInputEditText etServerUrl;
    private MaterialButton btnSaveUrl;
    private TextView tvConnectionTest;
    private SwitchCompat switchNotifications;
    private SeekBar seekbarInterval;
    private TextView tvPollInterval;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        prefs = new AppPrefs(this);

        etServerUrl        = findViewById(R.id.et_server_url);
        btnSaveUrl         = findViewById(R.id.btn_save_url);
        tvConnectionTest   = findViewById(R.id.tv_connection_test);
        switchNotifications= findViewById(R.id.switch_notifications);
        seekbarInterval    = findViewById(R.id.seekbar_interval);
        tvPollInterval     = findViewById(R.id.tv_poll_interval);

        // Load current values
        etServerUrl.setText(prefs.getServerUrl());
        switchNotifications.setChecked(prefs.areNotificationsEnabled());
        seekbarInterval.setProgress(prefs.getPollIntervalIndex());
        updateIntervalLabel(prefs.getPollIntervalIndex());

        btnSaveUrl.setOnClickListener(v -> saveAndTest());

        switchNotifications.setOnCheckedChangeListener((btn, checked) ->
                prefs.setNotificationsEnabled(checked));

        seekbarInterval.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                updateIntervalLabel(progress);
                prefs.setPollIntervalIndex(progress);
            }
            @Override public void onStartTrackingTouch(SeekBar seekBar) {}
            @Override public void onStopTrackingTouch(SeekBar seekBar) {}
        });
    }

    private void updateIntervalLabel(int index) {
        int secs = AppPrefs.POLL_INTERVALS[
                Math.min(index, AppPrefs.POLL_INTERVALS.length - 1)];
        String label = secs < 60 ? secs + "s" : (secs / 60) + "m";
        tvPollInterval.setText(label);
    }

    private void saveAndTest() {
        String url = etServerUrl.getText() != null
                ? etServerUrl.getText().toString().trim() : "";
        if (url.isEmpty()) {
            tvConnectionTest.setText("URL cannot be empty");
            tvConnectionTest.setTextColor(Color.parseColor("#D32F2F"));
            return;
        }
        if (!url.endsWith("/")) url += "/";

        prefs.setServerUrl(url);
        api = RetrofitClient.get(url);

        tvConnectionTest.setText("Testing connection...");
        tvConnectionTest.setTextColor(Color.parseColor("#FBC02D"));

        api.getRoot().enqueue(new Callback<RootResponse>() {
            @Override
            public void onResponse(Call<RootResponse> call, Response<RootResponse> response) {
                runOnUiThread(() -> {
                    if (response.isSuccessful() && response.body() != null) {
                        RootResponse root = response.body();
                        tvConnectionTest.setText("Connected! NexoraGuard v"
                                + root.version + " — " + root.scanner);
                        tvConnectionTest.setTextColor(Color.parseColor("#4CAF50"));
                    } else {
                        tvConnectionTest.setText("Connected but unexpected response (HTTP "
                                + response.code() + ")");
                        tvConnectionTest.setTextColor(Color.parseColor("#FBC02D"));
                    }
                });
            }

            @Override
            public void onFailure(Call<RootResponse> call, Throwable t) {
                runOnUiThread(() -> {
                    tvConnectionTest.setText("Failed: " + t.getMessage());
                    tvConnectionTest.setTextColor(Color.parseColor("#D32F2F"));
                });
            }
        });
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        startActivity(new Intent(this, MainActivity.class));
        overridePendingTransition(0, 0);
    }
}
