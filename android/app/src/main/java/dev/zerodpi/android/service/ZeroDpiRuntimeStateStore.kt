package dev.zerodpi.android.service

import android.app.ActivityManager
import android.content.Context

object ZeroDpiRuntimeStateStore {
    data class RuntimeMarker(
        val active: Boolean,
        val foregroundServiceExpected: Boolean,
        val profileId: String?,
        val updatedAtEpochMs: Long,
    ) {
        fun isStale(nowEpochMs: Long): Boolean =
            active && nowEpochMs - updatedAtEpochMs > STALE_RUNTIME_MARKER_TIMEOUT_MS
    }

    fun markRuntimeActive(context: Context, profileId: String? = null) {
        write(
            context = context,
            active = true,
            foregroundServiceExpected = true,
            profileId = profileId,
        )
    }

    fun markRuntimeInactive(context: Context) {
        write(
            context = context,
            active = false,
            foregroundServiceExpected = false,
            profileId = null,
        )
    }

    fun isRuntimeActive(
        context: Context,
        nowEpochMs: Long = System.currentTimeMillis(),
    ): Boolean {
        val marker = runtimeMarker(context)
        if (!marker.active) {
            return false
        }
        if (!marker.isStale(nowEpochMs)) {
            return true
        }
        if (marker.foregroundServiceExpected && isForegroundServiceActive(context)) {
            return true
        }
        markRuntimeInactive(context)
        return false
    }

    fun runtimeMarker(context: Context): RuntimeMarker {
        val prefs = context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return RuntimeMarker(
            active = prefs.getBoolean(KEY_RUNTIME_ACTIVE, false),
            foregroundServiceExpected = prefs.getBoolean(KEY_FOREGROUND_SERVICE_EXPECTED, false),
            profileId = prefs.getString(KEY_ACTIVE_PROFILE_ID, null),
            updatedAtEpochMs = prefs.getLong(KEY_UPDATED_AT_EPOCH_MS, 0L),
        )
    }

    private fun write(
        context: Context,
        active: Boolean,
        foregroundServiceExpected: Boolean,
        profileId: String?,
    ) {
        val editor = context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_RUNTIME_ACTIVE, active)
            .putBoolean(KEY_FOREGROUND_SERVICE_EXPECTED, foregroundServiceExpected)
            .putLong(KEY_UPDATED_AT_EPOCH_MS, System.currentTimeMillis())

        if (profileId != null) {
            editor.putString(KEY_ACTIVE_PROFILE_ID, profileId)
        } else if (!active) {
            editor.remove(KEY_ACTIVE_PROFILE_ID)
        }
        editor.apply()
    }

    @Suppress("DEPRECATION")
    private fun isForegroundServiceActive(context: Context): Boolean {
        val manager = context.applicationContext.getSystemService(ActivityManager::class.java)
            ?: return true
        return runCatching {
            manager.getRunningServices(Int.MAX_VALUE).any { service ->
                service.foreground && service.service.className == ZeroDpiService::class.java.name
            }
        }.getOrDefault(true)
    }

    private const val PREFS_NAME = "zerodpi-runtime-state"
    private const val KEY_RUNTIME_ACTIVE = "runtimeActive"
    private const val KEY_FOREGROUND_SERVICE_EXPECTED = "foregroundServiceExpected"
    private const val KEY_ACTIVE_PROFILE_ID = "activeProfileId"
    private const val KEY_UPDATED_AT_EPOCH_MS = "updatedAtEpochMs"
    private const val STALE_RUNTIME_MARKER_TIMEOUT_MS = 30 * 60 * 1_000L
}
