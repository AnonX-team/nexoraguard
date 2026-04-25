package com.nexora.securityagent;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.Query;

public interface ApiService {

    @GET("/")
    Call<RootResponse> getRoot();

    @GET("/status")
    Call<StatusResponse> getStatus();

    @GET("/analysis")
    Call<AnalysisResponse> getAnalysis();

    @GET("/scan")
    Call<AnalysisResponse> triggerScan();

    @GET("/alerts")
    Call<AlertsResponse> getAlerts(@Query("limit") int limit);

    @GET("/processes/suspicious")
    Call<ProcessesResponse> getSuspiciousProcesses();

    @GET("/processes")
    Call<ProcessesResponse> getAllProcesses(
            @Query("sort_by") String sortBy,
            @Query("limit") int limit
    );

    @GET("/network")
    Call<NetworkResponse> getNetwork();

    @GET("/integrity")
    Call<IntegrityResponse> checkIntegrity();

    @GET("/bruteforce/blocked")
    Call<BlockedResponse> getBlockedIps();

    @POST("/processes/kill")
    Call<KillResponse> killProcess(@Body KillRequest request);

    @POST("/chat")
    Call<ChatResponse> chat(@Body ChatRequest request);

    @GET("/timeline")
    Call<TimelineResponse> getTimeline(@Query("limit") int limit);
}

// Inline model for blocked IPs (simple)
class BlockedResponse {
    java.util.List<String> blocked;
    int count;
}
