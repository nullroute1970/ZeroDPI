package dev.zerodpi.android.profile

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

object ProfileAutoUpdateScheduler {
    suspend fun reconcile(
        context: Context,
        profileIndex: ProfileIndex? = null,
    ) {
        val appContext = context.applicationContext
        val index = profileIndex ?: runCatching {
            ProfileRepository(appContext).loadIndex()
        }.getOrNull()
        val repeatIntervalHours = index?.let(ProfileAutoUpdatePolicy::repeatIntervalHours)

        withContext(Dispatchers.Default) {
            val workManager = WorkManager.getInstance(appContext)
            if (repeatIntervalHours == null) {
                workManager.cancelUniqueWork(UNIQUE_WORK_NAME)
                return@withContext
            }

            val request = PeriodicWorkRequestBuilder<ProfileAutoUpdateWorker>(
                repeatIntervalHours,
                TimeUnit.HOURS,
            )
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .setRequiresBatteryNotLow(true)
                        .build(),
                )
                .addTag(WORK_TAG)
                .build()

            workManager.enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request,
            )
        }
    }

    private const val UNIQUE_WORK_NAME = "zerodpi-profile-auto-update"
    private const val WORK_TAG = "profile-auto-update"
}
