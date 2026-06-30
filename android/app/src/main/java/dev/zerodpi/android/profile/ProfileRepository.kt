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
}
