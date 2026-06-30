package dev.zerodpi.android.storage

import android.content.Context
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets

internal object RuntimeStorageLayout {
    const val RUNTIME_DIR_NAME = "zerodpi"
    const val LOGS_DIR_NAME = "logs"
    const val SCAN_RESULTS_DIR_NAME = "scan_results"
    const val ASSET_DIR = "zerodpi"
}

internal object RuntimeFileOps {
    fun ensureDirectory(directory: File) {
        if (!directory.isDirectory && !directory.mkdirs()) {
            error("Failed to create directory: ${directory.absolutePath}")
        }
    }

    fun backupFor(target: File): File {
        val parent = target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}")
        return File(parent, "${target.name}.bak")
    }

    fun restorePrimaryFromBackupIfMissing(target: File): Boolean {
        if (target.exists()) {
            return false
        }
        val backup = backupFor(target)
        if (!backup.isFile) {
            return false
        }
        copyFileAtomic(source = backup, target = target)
        return true
    }

    fun seedAssetIfMissing(
        context: Context,
        assetPath: String,
        target: File,
    ): Boolean {
        if (target.exists()) {
            return false
        }
        atomicWrite(
            target = target,
            content = readAssetText(context, assetPath),
            backup = null,
        )
        return true
    }

    fun readAssetText(context: Context, assetPath: String): String =
        context.assets.open(assetPath).use { input ->
            input.bufferedReader(StandardCharsets.UTF_8).readText()
        }

    fun atomicWrite(target: File, content: String, backup: File?) {
        val parent = target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}")
        ensureDirectory(parent)

        val temp = tempFileFor(target)
        try {
            FileOutputStream(temp).use { output ->
                output.write(content.toByteArray(StandardCharsets.UTF_8))
                output.fd.sync()
            }

            if (target.isFile && backup != null) {
                copyFileAtomic(source = target, target = backup)
            }

            renameReplacing(source = temp, target = target)
            fsyncDirectory(parent)
        } finally {
            if (temp.exists()) {
                temp.delete()
            }
        }
    }

    fun copyFileAtomic(source: File, target: File) {
        val parent = target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}")
        ensureDirectory(parent)

        val temp = tempFileFor(target)
        try {
            FileInputStream(source).use { input ->
                FileOutputStream(temp).use { output ->
                    input.copyTo(output)
                    output.fd.sync()
                }
            }
            renameReplacing(source = temp, target = target)
            fsyncDirectory(parent)
        } finally {
            if (temp.exists()) {
                temp.delete()
            }
        }
    }

    fun fsyncDirectory(directory: File) {
        runCatching {
            val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(fd)
            } finally {
                Os.close(fd)
            }
        }
    }

    private fun renameReplacing(source: File, target: File) {
        Os.rename(source.absolutePath, target.absolutePath)
    }

    private fun tempFileFor(target: File): File {
        val parent = target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}")
        return File(parent, ".${target.name}.${System.nanoTime()}.tmp")
    }
}
