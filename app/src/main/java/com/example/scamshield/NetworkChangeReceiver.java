package com.example.scamshield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;

public class NetworkChangeReceiver extends BroadcastReceiver {

    public interface NetworkListener {
        void onNetworkChanged(boolean isConnected);
    }

    private final NetworkListener listener;

    public NetworkChangeReceiver(NetworkListener listener) {
        this.listener = listener;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        ConnectivityManager manager =
                (ConnectivityManager) context.getSystemService(
                        Context.CONNECTIVITY_SERVICE);

        boolean connected = false;

        if (manager != null) {
            Network network = manager.getActiveNetwork();

            if (network != null) {
                NetworkCapabilities capabilities =
                        manager.getNetworkCapabilities(network);

                connected = capabilities != null
                        && capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        && capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_VALIDATED);
            }
        }

        if (listener != null) {
            listener.onNetworkChanged(connected);
        }
    }
}