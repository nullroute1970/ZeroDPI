package dev.zerodpi.android.runtime

import android.annotation.SuppressLint
import java.net.URLConnection
import java.util.concurrent.TimeUnit

/**
 * Version-safe wrappers around java.lang.Process / URLConnection APIs that
 * were added after the app's minSdk (23). Each helper first tries the modern
 * API and falls back to a legacy equivalent when the method does not exist
 * (NoSuchMethodError on old Android versions, or plain JVM test fakes that
 * only override the legacy methods).
 */
@SuppressLint("NewApi") // try/catch guards the modern API on pre-26 devices.
internal fun Process.isAliveCompat(): Boolean =
    try {
        isAlive
    } catch (_: Throwable) {
        // Pre-26 fallback: a process is alive while exitValue() throws.
        runCatching { exitValue() }.isFailure
    }

@SuppressLint("NewApi") // try/catch guards the modern API on pre-26 devices.
internal fun Process.destroyForciblyCompat() {
    try {
        destroyForcibly()
    } catch (_: Throwable) {
        destroy()
    }
}

/**
 * Blocking wait with a timeout. Pre-26 Process has no timed waitFor, so poll
 * exitValue() until the deadline. Must only be called from a background
 * thread (IO dispatcher), matching the post-26 semantics.
 */
@SuppressLint("NewApi") // try/catch guards the modern API on pre-26 devices.
internal fun Process.waitForCompat(timeout: Long, unit: TimeUnit): Boolean {
    try {
        return waitFor(timeout, unit)
    } catch (_: Throwable) {
        // Fall through to the polling fallback.
    }
    val deadline = System.currentTimeMillis() + unit.toMillis(timeout)
    while (System.currentTimeMillis() < deadline) {
        if (runCatching { exitValue() }.isSuccess) {
            return true
        }
        Thread.sleep(50)
    }
    return false
}

/**
 * Content length as Long; getContentLengthLong() only exists on API 24+.
 * Falls back to the (int) getContentLength() which is exact below 2 GiB.
 */
@SuppressLint("NewApi") // try/catch guards the modern API on pre-24 devices.
internal fun URLConnection.contentLengthLongCompat(): Long =
    try {
        contentLengthLong
    } catch (_: Throwable) {
        contentLength.toLong()
    }
