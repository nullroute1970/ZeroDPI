package dev.zerodpi.android.profile

import android.content.Context
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.storage.RuntimeFileOps
import dev.zerodpi.android.storage.RuntimeStorageLayout
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.UUID

data class ProfileFilePaths(
    val runtimeDir: File,
    val profilesDir: File,
    val profileDir: File,
    val configFile: File,
    val sniListFile: File,
    val ipListFile: File,
    val scanResultsDir: File,
) {
    fun fileFor(kind: RuntimeFileKind): File =
        when (kind) {
            RuntimeFileKind.Config -> configFile
            RuntimeFileKind.SniList -> sniListFile
            RuntimeFileKind.IpList -> ipListFile
        }
}

class ProfileRepositoryException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

class ProfileRepository(
    context: Context,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val idGenerator: () -> String = { UUID.randomUUID().toString() },
) {
    private val appContext = context.applicationContext
    private val runtimeDir = File(appContext.filesDir, RuntimeStorageLayout.RUNTIME_DIR_NAME)
    private val profilesDir = File(runtimeDir, ProfilePaths.PROFILES_DIR_NAME)
    private val indexFile = ProfilePaths.indexFile(runtimeDir)

    suspend fun loadIndex(): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                loadIndexLocked()
            }
        }

    suspend fun activeFilePaths(): ProfileFilePaths =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val index = loadIndexLocked()
                filePathsForKnownProfileLocked(index, index.activeProfileId)
            }
        }

    suspend fun filePaths(profileId: String): ProfileFilePaths =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val index = loadIndexLocked()
                filePathsForKnownProfileLocked(index, profileId)
            }
        }

    suspend fun createProfile(name: String): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val current = loadIndexLocked()
                val now = clock()
                val profile = ZeroDpiProfile(
                    id = generateProfileId(current.profiles.mapTo(mutableSetOf()) { it.id }),
                    name = name,
                    createdAtEpochMs = now,
                    updatedAtEpochMs = now,
                )
                val next = current.copy(profiles = current.profiles + profile).requireValid()
                seedProfileFilesFromAssetsLocked(filePathsFor(profile.id))
                writeIndexLocked(next)
            }
        }

    suspend fun renameProfile(profileId: String, name: String): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val current = loadIndexLocked()
                val existing = current.requireProfile(profileId)
                val renamed = existing.copy(
                    name = name,
                    updatedAtEpochMs = clock(),
                )
                val next = current.copy(
                    profiles = current.profiles.map { profile ->
                        if (profile.id == profileId) renamed else profile
                    },
                ).requireValid()
                writeIndexLocked(next)
            }
        }

    suspend fun updateProfile(profile: ZeroDpiProfile): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val current = loadIndexLocked()
                current.requireProfile(profile.id)
                val next = current.copy(
                    profiles = current.profiles.map { existing ->
                        if (existing.id == profile.id) profile else existing
                    },
                ).requireValid()
                writeIndexLocked(next)
            }
        }

    suspend fun updateRemoteSettings(
        profileId: String,
        remote: ProfileRemoteSettings,
    ): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val current = loadIndexLocked()
                val existing = current.requireProfile(profileId)
                val updated = existing.copy(
                    remote = remote,
                    updatedAtEpochMs = clock(),
                )
                val next = current.copy(
                    profiles = current.profiles.map { profile ->
                        if (profile.id == profileId) updated else profile
                    },
                ).requireValid()
                writeIndexLocked(next)
            }
        }

    suspend fun recordRemoteUpdateFailure(
        profileId: String,
        mode: ProfileUpdateMode,
        message: String,
        remote: ProfileRemoteSettings? = null,
    ): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val current = loadIndexLocked()
                val existing = current.requireProfile(profileId)
                val remoteForStatus = remote ?: existing.remote
                remoteForStatus.validate().requireValid("Profile remote settings")
                writeIndexLocked(
                    current.withUpdatedProfile(
                        existing.withRemoteUpdateStatus(
                            remote = remoteForStatus,
                            mode = mode,
                            successful = false,
                            message = message,
                            completedAtEpochMs = clock(),
                        ),
                    ),
                )
            }
        }

    suspend fun applyRemoteUpdate(
        profileId: String,
        remote: ProfileRemoteSettings,
        files: ProfileUpdateFileContents,
        mode: ProfileUpdateMode,
        message: String,
    ): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                remote.validateForUpdate().requireValid("Profile remote settings")
                val current = loadIndexLocked()
                val existing = current.requireProfile(profileId)
                val paths = filePathsForKnownProfileLocked(current, profileId)
                val updatedProfile = existing.withRemoteUpdateStatus(
                    remote = remote,
                    mode = mode,
                    successful = true,
                    message = message,
                    completedAtEpochMs = clock(),
                )
                val next = current.withUpdatedProfile(updatedProfile)
                val rollbackFiles = createRollbackFilesLocked(paths)

                try {
                    writeProfileFilesLocked(paths = paths, files = files)
                    writeIndexLocked(next)
                } catch (error: Exception) {
                    try {
                        restoreRollbackFilesLocked(rollbackFiles)
                    } catch (restoreError: Exception) {
                        restoreError.addSuppressed(error)
                        throw ProfileRepositoryException(
                            "Failed to apply remote update and restore previous profile files.",
                            restoreError,
                        )
                    }
                    throw ProfileRepositoryException(
                        "Failed to apply remote update; previous profile files were restored.",
                        error,
                    )
                } finally {
                    cleanupRollbackFilesLocked(rollbackFiles)
                }
            }
        }

    suspend fun duplicateProfile(
        sourceProfileId: String,
        name: String,
    ): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val current = loadIndexLocked()
                val source = current.requireProfile(sourceProfileId)
                val now = clock()
                val duplicate = ZeroDpiProfile(
                    id = generateProfileId(current.profiles.mapTo(mutableSetOf()) { it.id }),
                    name = name,
                    createdAtEpochMs = now,
                    updatedAtEpochMs = now,
                    remote = source.remote,
                )
                val next = current.copy(profiles = current.profiles + duplicate).requireValid()
                val sourcePaths = filePathsForKnownProfileLocked(current, sourceProfileId)
                val duplicatePaths = filePathsFor(duplicate.id)
                copyProfileFilesLocked(sourcePaths = sourcePaths, targetPaths = duplicatePaths)
                writeIndexLocked(next)
            }
        }

    suspend fun deleteProfile(profileId: String): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val current = loadIndexLocked()
                current.requireProfile(profileId)
                require(current.profiles.size > 1) { "Cannot delete the last profile." }

                val remaining = current.profiles.filterNot { it.id == profileId }
                val nextActiveProfileId = if (current.activeProfileId == profileId) {
                    remaining.first().id
                } else {
                    current.activeProfileId
                }
                val next = current.copy(
                    activeProfileId = nextActiveProfileId,
                    profiles = remaining,
                ).requireValid()
                val written = writeIndexLocked(next)
                val profileDir = filePathsFor(profileId).profileDir
                if (profileDir.exists()) {
                    profileDir.deleteRecursively()
                    RuntimeFileOps.fsyncDirectory(profilesDir)
                }
                written
            }
        }

    suspend fun selectProfile(profileId: String): ProfileIndex =
        withContext(Dispatchers.IO) {
            synchronized(repositoryLock) {
                val current = loadIndexLocked()
                current.requireProfile(profileId)
                writeIndexLocked(current.copy(activeProfileId = profileId).requireValid())
            }
        }

    private fun loadIndexLocked(): ProfileIndex {
        RuntimeFileOps.ensureDirectory(runtimeDir)
        RuntimeFileOps.ensureDirectory(profilesDir)
        RuntimeFileOps.restorePrimaryFromBackupIfMissing(indexFile)

        val index = if (indexFile.isFile) {
            readIndexLocked()
        } else {
            createDefaultIndexLocked()
        }
        ensureProfileStorageLocked(index)
        return index
    }

    private fun createDefaultIndexLocked(): ProfileIndex {
        val index = ProfileIndex.default(createdAtEpochMs = clock())
        val defaultPaths = filePathsFor(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        seedDefaultProfileFromLegacyOrAssetsLocked(defaultPaths)
        return writeIndexLocked(index)
    }

    private fun readIndexLocked(): ProfileIndex =
        try {
            ProfileIndex.fromJson(indexFile.readText(StandardCharsets.UTF_8))
        } catch (error: Exception) {
            throw ProfileRepositoryException(
                message = "Profile index is unreadable; profile files were left unchanged.",
                cause = error,
            )
        }

    private fun writeIndexLocked(index: ProfileIndex): ProfileIndex {
        val validIndex = index.requireValid()
        try {
            RuntimeFileOps.atomicWrite(
                target = indexFile,
                content = validIndex.toJson(),
                backup = RuntimeFileOps.backupFor(indexFile),
            )
        } catch (error: Exception) {
            throw ProfileRepositoryException("Failed to write profile index.", error)
        }
        return validIndex
    }

    private fun writeProfileFilesLocked(
        paths: ProfileFilePaths,
        files: ProfileUpdateFileContents,
    ) {
        RuntimeFileOps.atomicWrite(
            target = paths.configFile,
            content = files.configText,
            backup = RuntimeFileOps.backupFor(paths.configFile),
        )
        RuntimeFileOps.atomicWrite(
            target = paths.sniListFile,
            content = files.sniListText,
            backup = RuntimeFileOps.backupFor(paths.sniListFile),
        )
        RuntimeFileOps.atomicWrite(
            target = paths.ipListFile,
            content = files.ipListText,
            backup = RuntimeFileOps.backupFor(paths.ipListFile),
        )
    }

    private fun createRollbackFilesLocked(paths: ProfileFilePaths): List<ProfileFileRollback> =
        RuntimeFileKind.entries.map { kind ->
            val target = paths.fileFor(kind)
            val rollback = File(
                target.parentFile ?: error("Runtime target has no parent: ${target.absolutePath}"),
                ".${target.name}.${System.nanoTime()}.rollback",
            )
            val existed = target.exists()
            if (existed) {
                RuntimeFileOps.copyFileAtomic(source = target, target = rollback)
            }
            ProfileFileRollback(target = target, rollback = rollback, existed = existed)
        }

    private fun restoreRollbackFilesLocked(rollbackFiles: List<ProfileFileRollback>) {
        rollbackFiles.forEach { rollbackFile ->
            if (rollbackFile.existed) {
                RuntimeFileOps.copyFileAtomic(
                    source = rollbackFile.rollback,
                    target = rollbackFile.target,
                )
            } else if (rollbackFile.target.exists() && !rollbackFile.target.delete()) {
                error("Failed to remove new profile file: ${rollbackFile.target.absolutePath}")
            }
        }
        rollbackFiles.firstOrNull()?.target?.parentFile?.let(RuntimeFileOps::fsyncDirectory)
    }

    private fun cleanupRollbackFilesLocked(rollbackFiles: List<ProfileFileRollback>) {
        rollbackFiles.forEach { rollbackFile ->
            if (rollbackFile.rollback.exists()) {
                rollbackFile.rollback.delete()
            }
        }
    }

    private fun ensureProfileStorageLocked(index: ProfileIndex) {
        index.profiles.forEach { profile ->
            seedProfileFilesFromAssetsLocked(filePathsFor(profile.id))
        }
    }

    private fun filePathsForKnownProfileLocked(
        index: ProfileIndex,
        profileId: String,
    ): ProfileFilePaths {
        index.requireProfile(profileId)
        val paths = filePathsFor(profileId)
        seedProfileFilesFromAssetsLocked(paths)
        return paths
    }

    private fun seedDefaultProfileFromLegacyOrAssetsLocked(paths: ProfileFilePaths) {
        ensureProfileDirectories(paths)
        RuntimeFileKind.entries.forEach { kind ->
            val target = paths.fileFor(kind)
            RuntimeFileOps.restorePrimaryFromBackupIfMissing(target)
            if (!target.exists()) {
                val legacySource = legacySourceFor(kind)
                if (legacySource != null) {
                    RuntimeFileOps.copyFileAtomic(source = legacySource, target = target)
                } else {
                    seedProfileFileFromAsset(kind = kind, target = target)
                }
            }
        }
    }

    private fun seedProfileFilesFromAssetsLocked(paths: ProfileFilePaths) {
        ensureProfileDirectories(paths)
        RuntimeFileKind.entries.forEach { kind ->
            val target = paths.fileFor(kind)
            RuntimeFileOps.restorePrimaryFromBackupIfMissing(target)
            if (!target.exists()) {
                seedProfileFileFromAsset(kind = kind, target = target)
            }
        }
    }

    private fun copyProfileFilesLocked(
        sourcePaths: ProfileFilePaths,
        targetPaths: ProfileFilePaths,
    ) {
        ensureProfileDirectories(targetPaths)
        RuntimeFileKind.entries.forEach { kind ->
            RuntimeFileOps.copyFileAtomic(
                source = sourcePaths.fileFor(kind),
                target = targetPaths.fileFor(kind),
            )
        }
    }

    private fun seedProfileFileFromAsset(
        kind: RuntimeFileKind,
        target: File,
    ) {
        RuntimeFileOps.seedAssetIfMissing(
            context = appContext,
            assetPath = "${RuntimeStorageLayout.ASSET_DIR}/${kind.fileName}",
            target = target,
        )
    }

    private fun ensureProfileDirectories(paths: ProfileFilePaths) {
        RuntimeFileOps.ensureDirectory(paths.profileDir)
        RuntimeFileOps.ensureDirectory(paths.scanResultsDir)
    }

    private fun legacySourceFor(kind: RuntimeFileKind): File? {
        val primary = File(runtimeDir, kind.fileName)
        if (primary.isFile) {
            return primary
        }
        val backup = File(runtimeDir, "${kind.fileName}.bak")
        return backup.takeIf { it.isFile }
    }

    private fun filePathsFor(profileId: String): ProfileFilePaths {
        val profileDir = ProfilePaths.profileDirectory(profilesDir, profileId)
        return ProfileFilePaths(
            runtimeDir = runtimeDir,
            profilesDir = profilesDir,
            profileDir = profileDir,
            configFile = ProfilePaths.childFile(profileDir, RuntimeFileKind.Config.fileName),
            sniListFile = ProfilePaths.childFile(profileDir, RuntimeFileKind.SniList.fileName),
            ipListFile = ProfilePaths.childFile(profileDir, RuntimeFileKind.IpList.fileName),
            scanResultsDir = ProfilePaths.childFile(profileDir, RuntimeStorageLayout.SCAN_RESULTS_DIR_NAME),
        )
    }

    private fun ProfileIndex.requireProfile(profileId: String): ZeroDpiProfile {
        ZeroDpiProfile.validateId(profileId).requireValid("Profile id")
        return profiles.firstOrNull { it.id == profileId }
            ?: throw IllegalArgumentException("Unknown profile id: $profileId")
    }

    private fun ProfileIndex.withUpdatedProfile(profile: ZeroDpiProfile): ProfileIndex =
        copy(
            profiles = profiles.map { existing ->
                if (existing.id == profile.id) profile else existing
            },
        ).requireValid()

    private fun ZeroDpiProfile.withRemoteUpdateStatus(
        remote: ProfileRemoteSettings,
        mode: ProfileUpdateMode,
        successful: Boolean,
        message: String,
        completedAtEpochMs: Long,
    ): ZeroDpiProfile {
        val updatedRemote = remote.copy(
            lastUpdateAttemptEpochMs = completedAtEpochMs,
            lastSuccessfulUpdateEpochMs = if (successful) {
                completedAtEpochMs
            } else {
                remote.lastSuccessfulUpdateEpochMs
            },
            lastUpdateStatus = ProfileUpdateStatus(
                mode = mode,
                successful = successful,
                message = message,
                completedAtEpochMs = completedAtEpochMs,
            ),
        )
        return copy(
            remote = updatedRemote,
            updatedAtEpochMs = maxOf(createdAtEpochMs, updatedAtEpochMs, completedAtEpochMs),
        )
    }

    private fun generateProfileId(existingIds: Set<String>): String {
        repeat(MAX_ID_GENERATION_ATTEMPTS) {
            val candidate = idGenerator()
            if (candidate !in existingIds && ZeroDpiProfile.validateId(candidate).isValid) {
                return candidate
            }
        }
        throw ProfileRepositoryException("Failed to generate a unique profile id.")
    }

    private companion object {
        private const val MAX_ID_GENERATION_ATTEMPTS = 20
        private val repositoryLock = Any()
    }

    private data class ProfileFileRollback(
        val target: File,
        val rollback: File,
        val existed: Boolean,
    )
}
