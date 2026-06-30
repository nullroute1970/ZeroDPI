package dev.zerodpi.android.service

import android.content.Context

object ZeroDpiRuntimeStateStore {
    fun markRuntimeActive(context: Context) {
        write(context = context, active = true)
    }

    fun markRuntimeInactive(context: Context) {
        write(context = context, active = false)
    }

    fun isRuntimeActive(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_RUNTIME_ACTIVE, false)

    private fun write(context: Context, active: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_RUNTIME_ACTIVE, active)
            .putLong(KEY_UPDATED_AT_EPOCH_MS, System.currentTimeMillis())
            .apply()
    }

    private const val PREFS_NAME = "zerodpi-runtime-state"
    private const val KEY_RUNTIME_ACTIVE = "runtimeActive"
    private const val KEY_UPDATED_AT_EPOCH_MS = "updatedAtEpochMs"
}
