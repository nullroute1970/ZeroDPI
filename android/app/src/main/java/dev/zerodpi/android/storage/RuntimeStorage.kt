package dev.zerodpi.android.storage

import android.content.Context
import android.system.Os
import android.system.OsConstants
import dev.zerodpi.android.config.ZeroDpiConfigToml
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets

enum class RuntimeFileKind(
    val fileName: String,
    val title: String,
) {
    Config("config.toml", "Config"),
    SniList("sni_list.txt", "SNI list"),
    IpList("ip_list.txt", "IP list"),
}

data class RuntimeStorageFiles(
    val runtimeDir: File,
    val configFile: File,
    val sniListFile: File,
    val ipListFile: File,
    val logsDir: File,
    val scanResultsDir: File,
) {
    fun fileFor(kind: RuntimeFileKind): File =
        when (kind) {
            RuntimeFileKind.Config -> configFile
            RuntimeFileKind.SniList -> sniListFile
            RuntimeFileKind.IpList -> ipListFile
        }
}

data class RuntimeFileContents(
    val files: RuntimeStorageFiles,
    val configText: String,
    val sniListText: String,
    val ipListText: String,
)

data class RuntimeRunConfig(
    val files: RuntimeStorageFiles,
    val configFile: File,
    val configText: String,
    val modeOverride: String?,
)

data class ResolvedRuntimeConfigPaths(
    val sniList: File,
    val ipList: File,
    val scanOutput: File?,
)

class RuntimeStorage(context: Context) {
    private val appContext = context.applicationContext
    private val lock = Any()

    private val runtimeDir = File(appContext.filesDir, RUNTIME_DIR_NAME)
    private val files = RuntimeStorageFiles(
        runtimeDir = runtimeDir,
        configFile = File(runtimeDir, RuntimeFileKind.Config.fileName),
        sniListFile = File(runtimeDir, RuntimeFileKind.SniList.fileName),
        ipListFile = File(runtimeDir, RuntimeFileKind.IpList.fileName),
        logsDir = File(runtimeDir, LOGS_DIR_NAME),
        scanResultsDir = File(runtimeDir, SCAN_RESULTS_DIR_NAME),
    )

    suspend fun ensureInitialized(): RuntimeStorageFiles =
        withContext(Dispatchers.IO) {
            ensureInitializedBlocking()
        }

    suspend fun readAll(): RuntimeFileContents =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedBlocking()
            RuntimeFileContents(
                files = currentFiles,
                configText = currentFiles.configFile.readText(StandardCharsets.UTF_8),
                sniListText = currentFiles.sniListFile.readText(StandardCharsets.UTF_8),
                ipListText = currentFiles.ipListFile.readText(StandardCharsets.UTF_8),
            )
        }

    suspend fun save(kind: RuntimeFileKind, content: String) {
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedBlocking()
            val target = currentFiles.fileFor(kind)
            atomicWrite(target = target, content = content, backup = backupFor(target))
        }
    }

    suspend fun saveAll(
        configText: String,
        sniListText: String,
        ipListText: String,
    ) {
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedBlocking()
            atomicWrite(
                target = currentFiles.configFile,
                content = configText,
                backup = backupFor(currentFiles.configFile),
            )
            atomicWrite(
                target = currentFiles.sniListFile,
                content = sniListText,
                backup = backupFor(currentFiles.sniListFile),
            )
            atomicWrite(
                target = currentFiles.ipListFile,
                content = ipListText,
                backup = backupFor(currentFiles.ipListFile),
            )
        }
    }

    suspend fun resetToDefaults(kind: RuntimeFileKind): String =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedBlocking()
            val content = defaultContentFor(kind)
            val target = currentFiles.fileFor(kind)
            atomicWrite(target = target, content = content, backup = backupFor(target))
            content
        }

    suspend fun resolveConfigPaths(): ResolvedRuntimeConfigPaths =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedBlocking()
            resolveConfigPaths(currentFiles.configFile.readText(StandardCharsets.UTF_8))
        }

    suspend fun prepareConfiguredDirectories(): ResolvedRuntimeConfigPaths =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedBlocking()
            val configText = currentFiles.configFile.readText(StandardCharsets.UTF_8)
            val resolvedPaths = resolveConfigPaths(configText)
            resolvedPaths.scanOutput?.parentFile?.mkdirsOrThrow()
            resolvedPaths
        }

    suspend fun prepareRunConfig(modeOverride: String? = null): RuntimeRunConfig =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedBlocking()
            val storedConfigText = currentFiles.configFile.readText(StandardCharsets.UTF_8)
            val runConfigText = modeOverride?.let { mode ->
                ZeroDpiConfigToml.replaceOrAppendField(
                    text = storedConfigText,
                    fieldName = "MODE",
                    value = mode,
                )
            } ?: storedConfigText
            val runConfigFile = modeOverride?.let { mode ->
                File(currentFiles.runtimeDir, ".${mode}_config.toml").also { target ->
                    atomicWrite(target = target, content = runConfigText, backup = null)
                }
            } ?: currentFiles.configFile

            val resolvedPaths = resolveConfigPaths(runConfigText)
            resolvedPaths.scanOutput?.parentFile?.mkdirsOrThrow()

            RuntimeRunConfig(
                files = currentFiles,
                configFile = runConfigFile,
                configText = runConfigText,
                modeOverride = modeOverride,
            )
        }

    fun resolveConfigPaths(configText: String): ResolvedRuntimeConfigPaths =
        ResolvedRuntimeConfigPaths(
            sniList = resolveRuntimePath(
                readTomlString(configText, "SNI_LIST") ?: RuntimeFileKind.SniList.fileName,
            ),
            ipList = resolveRuntimePath(
                readTomlString(configText, "IP_LIST") ?: RuntimeFileKind.IpList.fileName,
            ),
            scanOutput = readTomlString(configText, "SCAN_OUTPUT")
                ?.takeIf { it.isNotBlank() }
                ?.let(::resolveRuntimePath),
        )

    private fun ensureInitializedBlocking(): RuntimeStorageFiles =
        synchronized(lock) {
            runtimeDir.mkdirsOrThrow()
            files.logsDir.mkdirsOrThrow()
            files.scanResultsDir.mkdirsOrThrow()

            restorePrimaryFromBackupIfMissing(files.configFile)
            restorePrimaryFromBackupIfMissing(files.sniListFile)
            restorePrimaryFromBackupIfMissing(files.ipListFile)

            seedIfMissing(files.configFile, RuntimeFileKind.Config)
            seedIfMissing(files.sniListFile, RuntimeFileKind.SniList)
            seedIfMissing(files.ipListFile, RuntimeFileKind.IpList)

            files
        }

    private fun seedIfMissing(target: File, kind: RuntimeFileKind) {
        if (target.exists()) {
            return
        }
        atomicWrite(target = target, content = defaultContentFor(kind), backup = null)
    }

    private fun restorePrimaryFromBackupIfMissing(target: File) {
        if (target.exists()) {
            return
        }
        val backup = backupFor(target)
        if (backup.isFile) {
            copyFileAtomic(source = backup, target = target)
        }
    }

    private fun backupFor(target: File): File {
        val parent = target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}")
        return File(parent, "${target.name}.bak")
    }

    private fun defaultContentFor(kind: RuntimeFileKind): String =
        appContext.assets.open("$ASSET_DIR/${kind.fileName}").use { input ->
            input.bufferedReader(StandardCharsets.UTF_8).readText()
        }

    private fun resolveRuntimePath(value: String): File {
        val raw = File(value)
        return if (raw.isAbsolute) {
            raw
        } else {
            File(runtimeDir, value)
        }
    }

    private fun readTomlString(content: String, key: String): String? {
        val pattern = Regex("(?m)^\\s*${Regex.escape(key)}\\s*=\\s*\"((?:\\\\.|[^\"\\\\])*)\"")
        val encoded = pattern.find(content)?.groupValues?.get(1) ?: return null
        return encoded
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    }

    private fun atomicWrite(target: File, content: String, backup: File?) {
        val parent = target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}")
        parent.mkdirsOrThrow()

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

    private fun copyFileAtomic(source: File, target: File) {
        val parent = target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}")
        parent.mkdirsOrThrow()

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

    private fun renameReplacing(source: File, target: File) {
        Os.rename(source.absolutePath, target.absolutePath)
    }

    private fun fsyncDirectory(directory: File) {
        runCatching {
            val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(fd)
            } finally {
                Os.close(fd)
            }
        }
    }

    private fun tempFileFor(target: File): File {
        val parent = target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}")
        return File(parent, ".${target.name}.${System.nanoTime()}.tmp")
    }

    private fun File.mkdirsOrThrow() {
        if (!isDirectory && !mkdirs()) {
            error("Failed to create directory: $absolutePath")
        }
    }

    private companion object {
        private const val RUNTIME_DIR_NAME = "zerodpi"
        private const val LOGS_DIR_NAME = "logs"
        private const val SCAN_RESULTS_DIR_NAME = "scan_results"
        private const val ASSET_DIR = "zerodpi"
    }
}
