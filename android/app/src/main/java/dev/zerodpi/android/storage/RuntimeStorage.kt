package dev.zerodpi.android.storage

import android.content.Context
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.diagnostics.DeviceDiagnostics
import dev.zerodpi.android.profile.ProfileFilePaths
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.profile.ZeroDpiProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

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
    val methodScanOutput: File?,
)

class RuntimeStorage(context: Context) {
    private val appContext = context.applicationContext
    private val profileRepository = ProfileRepository(appContext)
    private val lock = Any()
    private var activeLogFile: File? = null

    private val rootRuntimeDir = File(appContext.filesDir, RuntimeStorageLayout.RUNTIME_DIR_NAME)
    private val logsDir = File(rootRuntimeDir, RuntimeStorageLayout.LOGS_DIR_NAME)

    suspend fun ensureInitialized(profileId: String): RuntimeStorageFiles =
        withContext(Dispatchers.IO) {
            ensureInitializedForProfile(profileId)
        }

    suspend fun readAll(profileId: String): RuntimeFileContents =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            RuntimeFileContents(
                files = currentFiles,
                configText = currentFiles.configFile.readText(StandardCharsets.UTF_8),
                sniListText = currentFiles.sniListFile.readText(StandardCharsets.UTF_8),
                ipListText = currentFiles.ipListFile.readText(StandardCharsets.UTF_8),
            )
        }

    suspend fun readMethodScanOutput(profileId: String, configText: String): String? =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            val resolved = resolveConfigPaths(configText, currentFiles.runtimeDir)
            resolved.methodScanOutput
                ?.takeIf { it.isFile }
                ?.readText(StandardCharsets.UTF_8)
        }

    suspend fun save(profileId: String, kind: RuntimeFileKind, content: String) {
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            val target = currentFiles.fileFor(kind)
            RuntimeFileOps.atomicWrite(target = target, content = content, backup = RuntimeFileOps.backupFor(target))
        }
    }

    suspend fun saveAll(
        profileId: String,
        configText: String,
        sniListText: String,
        ipListText: String,
    ) {
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            RuntimeFileOps.atomicWrite(
                target = currentFiles.configFile,
                content = configText,
                backup = RuntimeFileOps.backupFor(currentFiles.configFile),
            )
            RuntimeFileOps.atomicWrite(
                target = currentFiles.sniListFile,
                content = sniListText,
                backup = RuntimeFileOps.backupFor(currentFiles.sniListFile),
            )
            RuntimeFileOps.atomicWrite(
                target = currentFiles.ipListFile,
                content = ipListText,
                backup = RuntimeFileOps.backupFor(currentFiles.ipListFile),
            )
        }
    }

    suspend fun resetToDefaults(profileId: String, kind: RuntimeFileKind): String =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            val content = defaultContentFor(kind)
            val target = currentFiles.fileFor(kind)
            RuntimeFileOps.atomicWrite(target = target, content = content, backup = RuntimeFileOps.backupFor(target))
            content
        }

    suspend fun resolveConfigPaths(profileId: String): ResolvedRuntimeConfigPaths =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            resolveConfigPaths(
                configText = currentFiles.configFile.readText(StandardCharsets.UTF_8),
                runtimeDir = currentFiles.runtimeDir,
            )
        }

    suspend fun prepareConfiguredDirectories(profileId: String): ResolvedRuntimeConfigPaths =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            val configText = currentFiles.configFile.readText(StandardCharsets.UTF_8)
            val resolvedPaths = resolveConfigPaths(configText, currentFiles.runtimeDir)
            resolvedPaths.scanOutput?.parentFile?.let(RuntimeFileOps::ensureDirectory)
            resolvedPaths.methodScanOutput?.parentFile?.let(RuntimeFileOps::ensureDirectory)
            resolvedPaths
        }

    suspend fun prepareRunConfig(profileId: String, modeOverride: String? = null): RuntimeRunConfig =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
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
                    RuntimeFileOps.atomicWrite(target = target, content = runConfigText, backup = null)
                }
            } ?: currentFiles.configFile

            val resolvedPaths = resolveConfigPaths(runConfigText, currentFiles.runtimeDir)
            resolvedPaths.scanOutput?.parentFile?.let(RuntimeFileOps::ensureDirectory)
            resolvedPaths.methodScanOutput?.parentFile?.let(RuntimeFileOps::ensureDirectory)

            RuntimeRunConfig(
                files = currentFiles,
                configFile = runConfigFile,
                configText = runConfigText,
                modeOverride = modeOverride,
            )
        }

    suspend fun startNewLogSession(label: String): File =
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                ensureLogStorageBlocking()
                activeLogFile = File(
                    logsDir,
                    "${timestampForFile()}_${label.sanitizeFileName()}.log",
                )
                pruneLogFiles(logsDir)
                activeLogFile ?: error("Failed to create log session.")
            }
        }

    suspend fun appendLogLine(message: String) {
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                ensureLogStorageBlocking()
                val target = activeLogFile ?: File(logsDir, "${timestampForFile()}_session.log").also {
                    activeLogFile = it
                    pruneLogFiles(logsDir)
                }
                FileOutputStream(target, true).use { output ->
                    output.write("${timestampForLog()} $message\n".toByteArray(StandardCharsets.UTF_8))
                }
            }
        }
    }

    suspend fun clearLogs() {
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                ensureLogStorageBlocking()
                activeLogFile = null
                val failedDeletes = logsDir.listFiles { file -> file.isFile && file.extension == "log" }
                    .orEmpty()
                    .filterNot(File::delete)
                check(failedDeletes.isEmpty()) {
                    "Could not delete ${failedDeletes.joinToString { it.name }}."
                }
            }
        }
    }

    suspend fun exportSupportBundle(
        profileId: String,
        output: OutputStream,
        diagnostics: DeviceDiagnostics,
        includePrivateLists: Boolean,
    ) {
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            val profile = profileFor(profileId)
            val configText = currentFiles.configFile.readText(StandardCharsets.UTF_8)
            ZipOutputStream(output).use { zip ->
                zip.addText("README.txt", SupportBundleSanitizer.noticeText(includePrivateLists))
                zip.addText("diagnostics.txt", diagnostics.asText())
                zip.addText("profile.txt", SupportBundleSanitizer.profileMetadata(profile))
                zip.addText("config.redacted.toml", SupportBundleSanitizer.sanitizedConfig(configText))
                recentLogFiles(currentFiles.logsDir).forEach { logFile ->
                    zip.addFile("logs/${logFile.name}", logFile)
                }
                if (includePrivateLists) {
                    zip.addFile(RuntimeFileKind.SniList.fileName, currentFiles.sniListFile)
                    zip.addFile(RuntimeFileKind.IpList.fileName, currentFiles.ipListFile)
                } else {
                    zip.addText(
                        "lists_omitted.txt",
                        "sni_list.txt and ip_list.txt were omitted because they may contain private production targets.\n",
                    )
                }
            }
        }
    }

    fun resolveConfigPaths(configText: String, runtimeDir: File): ResolvedRuntimeConfigPaths =
        ResolvedRuntimeConfigPaths(
            sniList = resolveRuntimePath(
                readTomlString(configText, "SNI_LIST") ?: RuntimeFileKind.SniList.fileName,
                runtimeDir,
            ),
            ipList = resolveRuntimePath(
                readTomlString(configText, "IP_LIST") ?: RuntimeFileKind.IpList.fileName,
                runtimeDir,
            ),
            scanOutput = readTomlString(configText, "SCAN_OUTPUT")
                ?.takeIf { it.isNotBlank() }
                ?.let { resolveRuntimePath(it, runtimeDir) },
            methodScanOutput = readTomlString(configText, "METHOD_SCAN_OUTPUT")
                ?.takeIf { it.isNotBlank() }
                ?.let { resolveRuntimePath(it, runtimeDir) },
        )

    private suspend fun ensureInitializedForProfile(profileId: String): RuntimeStorageFiles {
        val profilePaths = profileRepository.filePaths(profileId)
        return synchronized(lock) {
            val files = runtimeFilesFor(profilePaths)
            RuntimeFileOps.ensureDirectory(rootRuntimeDir)
            RuntimeFileOps.ensureDirectory(files.runtimeDir)
            RuntimeFileOps.ensureDirectory(files.logsDir)
            RuntimeFileOps.ensureDirectory(files.scanResultsDir)

            RuntimeFileOps.restorePrimaryFromBackupIfMissing(files.configFile)
            RuntimeFileOps.restorePrimaryFromBackupIfMissing(files.sniListFile)
            RuntimeFileOps.restorePrimaryFromBackupIfMissing(files.ipListFile)

            seedIfMissing(files.configFile, RuntimeFileKind.Config)
            seedIfMissing(files.sniListFile, RuntimeFileKind.SniList)
            seedIfMissing(files.ipListFile, RuntimeFileKind.IpList)

            files
        }
    }

    private fun ensureLogStorageBlocking() {
        RuntimeFileOps.ensureDirectory(rootRuntimeDir)
        RuntimeFileOps.ensureDirectory(logsDir)
    }

    private suspend fun profileFor(profileId: String): ZeroDpiProfile {
        val index = profileRepository.loadIndex()
        return index.profiles.firstOrNull { it.id == profileId }
            ?: throw IllegalArgumentException("Unknown profile id: $profileId")
    }

    private fun runtimeFilesFor(paths: ProfileFilePaths): RuntimeStorageFiles =
        RuntimeStorageFiles(
            runtimeDir = paths.profileDir,
            configFile = paths.configFile,
            sniListFile = paths.sniListFile,
            ipListFile = paths.ipListFile,
            logsDir = logsDir,
            scanResultsDir = paths.scanResultsDir,
        )

    private fun seedIfMissing(target: File, kind: RuntimeFileKind) {
        if (target.exists()) {
            return
        }
        RuntimeFileOps.atomicWrite(target = target, content = defaultContentFor(kind), backup = null)
    }

    private fun defaultContentFor(kind: RuntimeFileKind): String =
        RuntimeFileOps.readAssetText(
            context = appContext,
            assetPath = "${RuntimeStorageLayout.ASSET_DIR}/${kind.fileName}",
        )

    private fun resolveRuntimePath(value: String, runtimeDir: File): File {
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

    private fun recentLogFiles(logsDir: File): List<File> =
        logsDir.listFiles { file -> file.isFile && file.extension == "log" }
            ?.sortedByDescending { it.lastModified() }
            ?.take(MAX_LOG_FILES_IN_BUNDLE)
            ?.reversed()
            .orEmpty()

    private fun pruneLogFiles(logsDir: File) {
        logsDir.listFiles { file -> file.isFile && file.extension == "log" }
            ?.sortedByDescending { it.lastModified() }
            ?.drop(MAX_RETAINED_LOG_FILES)
            ?.forEach { it.delete() }
    }

    private fun ZipOutputStream.addText(name: String, text: String) {
        putNextEntry(ZipEntry(name))
        write(text.toByteArray(StandardCharsets.UTF_8))
        closeEntry()
    }

    private fun ZipOutputStream.addFile(name: String, file: File) {
        if (!file.isFile) {
            return
        }
        putNextEntry(ZipEntry(name))
        FileInputStream(file).use { input ->
            input.copyTo(this)
        }
        closeEntry()
    }

    private fun timestampForFile(): String =
        SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.US).format(Date())

    private fun timestampForLog(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())

    private fun String.sanitizeFileName(): String =
        replace(Regex("""[^A-Za-z0-9_.-]"""), "_").ifBlank { "session" }

    private companion object {
        private const val MAX_RETAINED_LOG_FILES = 8
        private const val MAX_LOG_FILES_IN_BUNDLE = 4
    }
}
