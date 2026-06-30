package dev.zerodpi.android.profile

internal object ProfileAutoUpdatePolicy {
    fun enabledProfiles(index: ProfileIndex): List<ZeroDpiProfile> =
        index.profiles.filter { profile -> profile.remote.autoUpdateEnabled }

    fun dueProfiles(index: ProfileIndex, nowEpochMs: Long): List<ZeroDpiProfile> =
        enabledProfiles(index).filter { profile ->
            isDue(remote = profile.remote, nowEpochMs = nowEpochMs)
        }

    fun repeatIntervalHours(index: ProfileIndex): Long? =
        enabledProfiles(index).minOfOrNull { profile ->
            profile.remote.autoUpdateIntervalHours.coerceAtLeast(MIN_INTERVAL_HOURS).toLong()
        }

    private fun isDue(remote: ProfileRemoteSettings, nowEpochMs: Long): Boolean {
        if (!remote.autoUpdateEnabled) {
            return false
        }
        val lastAttempt = remote.lastUpdateAttemptEpochMs ?: return true
        if (nowEpochMs < lastAttempt) {
            return false
        }
        val intervalMillis = remote.autoUpdateIntervalHours
            .coerceAtLeast(MIN_INTERVAL_HOURS)
            .toLong() * MILLIS_PER_HOUR
        return nowEpochMs - lastAttempt >= intervalMillis
    }

    private const val MIN_INTERVAL_HOURS = 1
    private const val MILLIS_PER_HOUR = 60L * 60L * 1000L
}
