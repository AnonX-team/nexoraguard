package com.nexora.securityagent;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Simple SharedPreferences wrapper for app-wide settings.
 */
public class AppPrefs {

    private static final String PREFS_NAME = "nexoraguard_prefs";
    private static final String KEY_SERVER_URL = "server_url";
    private static final String KEY_NOTIFICATIONS = "notifications_enabled";
    private static final String KEY_POLL_INTERVAL = "poll_interval_index";

    public static final String DEFAULT_URL = "http://192.168.1.100:8000/";

    // Intervals in seconds mapped to seekbar positions 0-5
    public static final int[] POLL_INTERVALS = {15, 30, 60, 120, 300, 600};

    private final SharedPreferences prefs;

    public AppPrefs(Context context) {
        prefs = context.getApplicationContext()
                       .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public String getServerUrl() {
        return prefs.getString(KEY_SERVER_URL, DEFAULT_URL);
    }

    public void setServerUrl(String url) {
        prefs.edit().putString(KEY_SERVER_URL, url).apply();
    }

    public boolean areNotificationsEnabled() {
        return prefs.getBoolean(KEY_NOTIFICATIONS, true);
    }

    public void setNotificationsEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_NOTIFICATIONS, enabled).apply();
    }

    public int getPollIntervalIndex() {
        return prefs.getInt(KEY_POLL_INTERVAL, 1); // default = 30s
    }

    public void setPollIntervalIndex(int index) {
        prefs.edit().putInt(KEY_POLL_INTERVAL, index).apply();
    }

    public int getPollIntervalSeconds() {
        int idx = getPollIntervalIndex();
        if (idx < 0 || idx >= POLL_INTERVALS.length) return 30;
        return POLL_INTERVALS[idx];
    }
}
