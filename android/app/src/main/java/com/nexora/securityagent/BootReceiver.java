package com.nexora.securityagent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * Restarts the ThreatPollingService after device reboot if
 * the app was previously running.
 */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Intent serviceIntent = new Intent(context, ThreatPollingService.class);
            context.startService(serviceIntent);
        }
    }
}
