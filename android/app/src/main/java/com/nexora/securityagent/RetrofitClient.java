package com.nexora.securityagent;

import okhttp3.OkHttpClient;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import java.util.concurrent.TimeUnit;

/**
 * Singleton Retrofit client. Call RetrofitClient.get(url) whenever the
 * server URL changes (e.g. after the user saves a new URL in Settings).
 */
public class RetrofitClient {

    private static ApiService instance;
    private static String currentBaseUrl = "";

    public static ApiService get(String baseUrl) {
        if (!baseUrl.equals(currentBaseUrl) || instance == null) {
            currentBaseUrl = baseUrl;
            OkHttpClient client = new OkHttpClient.Builder()
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .writeTimeout(30, TimeUnit.SECONDS)
                    .build();

            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl(baseUrl)
                    .client(client)
                    .addConverterFactory(GsonConverterFactory.create())
                    .build();
            instance = retrofit.create(ApiService.class);
        }
        return instance;
    }
}
