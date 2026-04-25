package com.nexora.securityagent;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class NetworkActivity extends AppCompatActivity {

    private ApiService api;
    private AppPrefs prefs;

    private RecyclerView recyclerConnections;
    private SwipeRefreshLayout swipeRefresh;
    private TextView tvBytesSent, tvBytesRecv;
    private MaterialButton btnFilterAll, btnFilterSuspicious;

    private ConnectionsAdapter adapter;
    private List<NetworkResponse.Connection> allConnections = new ArrayList<>();
    private boolean showOnlySuspicious = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_network);

        prefs = new AppPrefs(this);
        api = RetrofitClient.get(prefs.getServerUrl());

        recyclerConnections = findViewById(R.id.recycler_connections);
        swipeRefresh        = findViewById(R.id.swipe_refresh);
        tvBytesSent         = findViewById(R.id.tv_bytes_sent);
        tvBytesRecv         = findViewById(R.id.tv_bytes_recv);
        btnFilterAll        = findViewById(R.id.btn_filter_all);
        btnFilterSuspicious = findViewById(R.id.btn_filter_suspicious);

        adapter = new ConnectionsAdapter(new ArrayList<>());
        recyclerConnections.setAdapter(adapter);
        recyclerConnections.setLayoutManager(new LinearLayoutManager(this));

        swipeRefresh.setColorSchemeColors(Color.parseColor("#00E5FF"));
        swipeRefresh.setProgressBackgroundColorSchemeColor(Color.parseColor("#1A1A2E"));
        swipeRefresh.setOnRefreshListener(this::loadNetwork);

        btnFilterAll.setOnClickListener(v -> {
            showOnlySuspicious = false;
            updateFilterButtons();
            applyFilter();
        });

        btnFilterSuspicious.setOnClickListener(v -> {
            showOnlySuspicious = true;
            updateFilterButtons();
            applyFilter();
        });

        loadNetwork();
    }

    private void loadNetwork() {
        swipeRefresh.setRefreshing(true);
        api.getNetwork().enqueue(new Callback<NetworkResponse>() {
            @Override
            public void onResponse(Call<NetworkResponse> call, Response<NetworkResponse> response) {
                swipeRefresh.setRefreshing(false);
                if (!response.isSuccessful() || response.body() == null) return;
                NetworkResponse net = response.body();

                allConnections = net.connections != null ? net.connections : new ArrayList<>();

                runOnUiThread(() -> {
                    if (net.stats != null) {
                        tvBytesSent.setText(String.format(Locale.US,
                                "%.1f MB", net.stats.bytes_sent_mb));
                        tvBytesRecv.setText(String.format(Locale.US,
                                "%.1f MB", net.stats.bytes_recv_mb));
                    }
                    applyFilter();
                });
            }

            @Override
            public void onFailure(Call<NetworkResponse> call, Throwable t) {
                swipeRefresh.setRefreshing(false);
            }
        });
    }

    private void applyFilter() {
        List<NetworkResponse.Connection> filtered = new ArrayList<>();
        for (NetworkResponse.Connection c : allConnections) {
            if (!showOnlySuspicious || c.suspicious_port) {
                filtered.add(c);
            }
        }
        adapter.update(filtered);
    }

    private void updateFilterButtons() {
        if (showOnlySuspicious) {
            btnFilterAll.setBackgroundColor(Color.parseColor("#1A1A2E"));
            btnFilterAll.setTextColor(Color.parseColor("#888888"));
            btnFilterSuspicious.setBackgroundColor(Color.parseColor("#00E5FF"));
            btnFilterSuspicious.setTextColor(Color.parseColor("#0D0D0D"));
        } else {
            btnFilterAll.setBackgroundColor(Color.parseColor("#00E5FF"));
            btnFilterAll.setTextColor(Color.parseColor("#0D0D0D"));
            btnFilterSuspicious.setBackgroundColor(Color.parseColor("#1A1A2E"));
            btnFilterSuspicious.setTextColor(Color.parseColor("#888888"));
        }
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

    static class ConnectionsAdapter extends RecyclerView.Adapter<ConnectionsAdapter.VH> {

        private List<NetworkResponse.Connection> items;

        ConnectionsAdapter(List<NetworkResponse.Connection> items) {
            this.items = items;
        }

        void update(List<NetworkResponse.Connection> newItems) {
            this.items = newItems;
            notifyDataSetChanged();
        }

        @Override
        public VH onCreateViewHolder(ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_connection, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(VH h, int position) {
            NetworkResponse.Connection c = items.get(position);

            String remote = c.remote_addr != null && !c.remote_addr.isEmpty()
                    ? c.remote_addr : "(listening)";
            h.tvRemoteAddr.setText(remote);
            h.tvLocalAddr.setText(c.local_addr != null ? c.local_addr : "");
            h.tvStatus.setText(c.status != null ? c.status : "");
            h.tvPid.setText(c.pid > 0 ? "PID " + c.pid : "");

            int dotColor = c.suspicious_port
                    ? Color.parseColor("#D32F2F") : Color.parseColor("#4CAF50");
            h.viewSuspicious.setBackgroundColor(dotColor);

            int statusColor = c.suspicious_port
                    ? Color.parseColor("#F57C00") : Color.parseColor("#4CAF50");
            h.tvStatus.setTextColor(statusColor);
        }

        @Override
        public int getItemCount() {
            return items.size();
        }

        static class VH extends RecyclerView.ViewHolder {
            View viewSuspicious;
            TextView tvRemoteAddr, tvLocalAddr, tvStatus, tvPid;

            VH(View v) {
                super(v);
                viewSuspicious = v.findViewById(R.id.view_suspicious);
                tvRemoteAddr   = v.findViewById(R.id.tv_remote_addr);
                tvLocalAddr    = v.findViewById(R.id.tv_local_addr);
                tvStatus       = v.findViewById(R.id.tv_status);
                tvPid          = v.findViewById(R.id.tv_pid);
            }
        }
    }
}
