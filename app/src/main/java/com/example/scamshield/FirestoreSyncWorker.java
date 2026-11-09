
package com.example.scamshield;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Constraints;
import androidx.work.ExistingWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import com.google.firebase.auth.FirebaseAuth;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class FirestoreSyncWorker extends Worker {

    private static final String TAG = "FirestoreSyncWorker";
    private static final String WORK_NAME = "firestore_scan_sync";

    public FirestoreSyncWorker(
            @NonNull Context context,
            @NonNull WorkerParameters params
    ) {
        super(context, params);
    }

    public static void schedule(Context context) {

        Constraints constraints = new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build();

        OneTimeWorkRequest request =
                new OneTimeWorkRequest.Builder(FirestoreSyncWorker.class)
                        .setConstraints(constraints)
                        .setBackoffCriteria(
                                androidx.work.BackoffPolicy.EXPONENTIAL,
                                30,
                                TimeUnit.SECONDS
                        )
                        .build();

        WorkManager.getInstance(context.getApplicationContext())
                .enqueueUniqueWork(
                        WORK_NAME,
                        ExistingWorkPolicy.APPEND_OR_REPLACE,
                        request
                );
    }

    public static void cancel(Context context) {
        WorkManager.getInstance(context.getApplicationContext())
                .cancelUniqueWork(WORK_NAME);
    }

    @NonNull
    @Override
    public Result doWork() {

        if (FirebaseAuth.getInstance().getCurrentUser() == null) {
            Log.w(TAG, "No authenticated user. Retrying later.");
            return Result.retry();
        }

        ScanDatabaseHelper database =
                new ScanDatabaseHelper(getApplicationContext());

        try {

            // STEP 1: Upload pending scans to Firestore.
            List<ScanRecord> pendingScans =
                    database.getPendingScans();

            for (ScanRecord scan : pendingScans) {

                if (isStopped()) {
                    return Result.retry();
                }

                CountDownLatch latch = new CountDownLatch(1);
                AtomicBoolean uploadSuccessful = new AtomicBoolean(false);

                FirestoreSync.uploadScan(
                        scan,
                        new FirestoreSync.SyncCallback() {

                            @Override
                            public void onSuccess() {
                                uploadSuccessful.set(true);
                                latch.countDown();
                            }

                            @Override
                            public void onFailure(Exception error) {
                                Log.e(TAG, "Firestore upload failed.", error);
                                latch.countDown();
                            }
                        }
                );

                boolean completed;

                try {
                    completed = latch.await(25, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return Result.retry();
                }

                if (!completed || !uploadSuccessful.get()) {
                    return Result.retry();
                }

                database.markScanAsSynced(scan.getId());

                Log.d(TAG, "Scan synchronized: " + scan.getId());
            }

            // STEP 2: Recalculate statistics from SQLite.
            int messages = database.getMessageScanCount();
            int urls = database.getUrlScanCount();
            int highRisk = database.getThreatCount();
            long lastScan = database.getLastScanAt();

            // STEP 3: Synchronize statistics with Firebase RTDB.
            CountDownLatch statsLatch = new CountDownLatch(1);
            AtomicBoolean statsSuccessful = new AtomicBoolean(false);

            RealtimeDatabaseManager.syncScanStatistics(
                    messages,
                    urls,
                    highRisk,
                    lastScan,
                    new RealtimeDatabaseManager.UpdateCallback() {

                        @Override
                        public void onSuccess() {
                            statsSuccessful.set(true);
                            statsLatch.countDown();
                        }

                        @Override
                        public void onFailure(Exception error) {
                            Log.e(TAG, "Statistics sync failed.", error);
                            statsLatch.countDown();
                        }
                    }
            );

            boolean statsCompleted;

            try {
                statsCompleted = statsLatch.await(
                        25, TimeUnit.SECONDS
                );
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Result.retry();
            }

            if (!statsCompleted || !statsSuccessful.get()) {
                return Result.retry();
            }

            Log.d(TAG, "All scan statistics synchronized successfully.");

            return Result.success();

        } catch (Exception e) {

            Log.e(TAG, "Background synchronization error.", e);
            return Result.retry();

        } finally {
            database.close();
        }
    }
}
