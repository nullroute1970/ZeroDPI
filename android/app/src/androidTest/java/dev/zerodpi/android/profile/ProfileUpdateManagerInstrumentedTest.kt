package dev.zerodpi.android.profile

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zerodpi.android.storage.RuntimeFileKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

@RunWith(AndroidJUnit4::class)
class ProfileUpdateManagerInstrumentedTest {
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        clearRuntimeDir()
    }

    @After
    fun tearDown() {
        clearRuntimeDir()
    }

    @Test
    fun successfulRemoteUpdateOverwritesAllProfileFilesAndRecordsStatus() = runBlocking {
        val repository = repository(clock = sequenceClock(1000L, 2000L))
        repository.loadIndex()
        val paths = repository.activeFilePaths()
        val oldFiles = profileFileTexts(paths)
        val remote = remoteSettings()
        val remoteFiles = ProfileUpdateFileContents(
            configText = assetText(RuntimeFileKind.Config).replace("AUTO_SELECT = false", "AUTO_SELECT = true"),
            sniListText = "remote.example.com\n",
            ipListText = "203.0.113.10\n2001:db8::1\n",
        )
        val manager = ProfileUpdateManager(
            profileRepository = repository,
            remoteClient = fakeClient(remote = remote, files = remoteFiles),
        )

        val result = manager.updateProfile(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            mode = ProfileUpdateMode.Manual,
            remote = remote,
        )
        val status = result.index.profiles.single().remote.lastUpdateStatus!!

        assertTrue(result.successful)
        assertEquals(remoteFiles.configText, paths.configFile.readText(StandardCharsets.UTF_8))
        assertEquals(remoteFiles.sniListText, paths.sniListFile.readText(StandardCharsets.UTF_8))
        assertEquals(remoteFiles.ipListText, paths.ipListFile.readText(StandardCharsets.UTF_8))
        assertEquals(oldFiles[RuntimeFileKind.Config], File(paths.profileDir, "config.toml.bak").readText(StandardCharsets.UTF_8))
        assertTrue(status.successful)
        assertEquals(ProfileUpdateMode.Manual, status.mode)
        assertEquals(2000L, status.completedAtEpochMs)
        assertEquals(2000L, result.index.profiles.single().remote.lastSuccessfulUpdateEpochMs)
    }

    @Test
    fun partialRemoteDownloadFailureOverwritesNoProfileFilesAndRecordsStatus() = runBlocking {
        val repository = repository(clock = sequenceClock(1000L, 2000L))
        repository.loadIndex()
        val paths = repository.activeFilePaths()
        val oldFiles = profileFileTexts(paths)
        val remote = remoteSettings()
        val remoteFiles = ProfileUpdateFileContents(
            configText = assetText(RuntimeFileKind.Config).replace("AUTO_SELECT = false", "AUTO_SELECT = true"),
            sniListText = "remote.example.com\n",
            ipListText = "203.0.113.10\n",
        )
        val manager = ProfileUpdateManager(
            profileRepository = repository,
            remoteClient = fakeClient(
                remote = remote,
                files = remoteFiles,
                failures = mapOf(ProfileRemoteFile.SniList to "HTTP 404 while downloading sni_list.txt."),
            ),
        )

        val result = manager.updateProfile(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            mode = ProfileUpdateMode.Manual,
            remote = remote,
        )
        val status = result.index.profiles.single().remote.lastUpdateStatus!!

        assertFalse(result.successful)
        assertEquals(oldFiles, profileFileTexts(paths))
        assertFalse(status.successful)
        assertTrue(status.message.contains("sni_list.txt"))
        assertEquals(2000L, status.completedAtEpochMs)
    }

    @Test
    fun invalidRemoteListOverwritesNoProfileFilesAndRecordsStatus() = runBlocking {
        val repository = repository(clock = sequenceClock(1000L, 2000L))
        repository.loadIndex()
        val paths = repository.activeFilePaths()
        val oldFiles = profileFileTexts(paths)
        val remote = remoteSettings()
        val remoteFiles = ProfileUpdateFileContents(
            configText = assetText(RuntimeFileKind.Config),
            sniListText = "bad host name\n",
            ipListText = "203.0.113.10\n",
        )
        val manager = ProfileUpdateManager(
            profileRepository = repository,
            remoteClient = fakeClient(remote = remote, files = remoteFiles),
        )

        val result = manager.updateProfile(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            mode = ProfileUpdateMode.Manual,
            remote = remote,
        )
        val status = result.index.profiles.single().remote.lastUpdateStatus!!

        assertFalse(result.successful)
        assertEquals(oldFiles, profileFileTexts(paths))
        assertFalse(status.successful)
        assertTrue(status.message.startsWith("sni_list.txt validation failed"))
    }

    @Test
    fun applyGuardFailureOverwritesNoProfileFilesAndRecordsAutomaticStatus() = runBlocking {
        val repository = repository(clock = sequenceClock(1000L, 2000L))
        repository.loadIndex()
        val paths = repository.activeFilePaths()
        val oldFiles = profileFileTexts(paths)
        val remote = remoteSettings()
        val remoteFiles = ProfileUpdateFileContents(
            configText = assetText(RuntimeFileKind.Config),
            sniListText = "remote.example.com\n",
            ipListText = "203.0.113.10\n",
        )
        val manager = ProfileUpdateManager(
            profileRepository = repository,
            remoteClient = fakeClient(remote = remote, files = remoteFiles),
            beforeApply = {
                error("Automatic update skipped because ZeroDPI started running.")
            },
        )

        val result = manager.updateProfile(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            mode = ProfileUpdateMode.Automatic,
            remote = remote,
        )
        val status = result.index.profiles.single().remote.lastUpdateStatus!!

        assertFalse(result.successful)
        assertEquals(oldFiles, profileFileTexts(paths))
        assertFalse(status.successful)
        assertEquals(ProfileUpdateMode.Automatic, status.mode)
        assertTrue(status.message.contains("ZeroDPI started running"))
    }

    @Test
    fun manualUpdateFromRealHttpsUrlsOverwritesProfileFiles() = runBlocking {
        val remote = githubRawRemoteSettings()
        assumeTrue("GitHub raw HTTPS runtime assets are not reachable.", remoteUrlsReachable(remote))
        val repository = repository(clock = sequenceClock(1000L, 2000L))
        repository.loadIndex()
        val manager = ProfileUpdateManager(profileRepository = repository)

        val result = manager.updateProfile(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            mode = ProfileUpdateMode.Manual,
            remote = remote,
        )
        val paths = repository.activeFilePaths()
        val status = result.index.profiles.single().remote.lastUpdateStatus!!

        assertTrue(result.message, result.successful)
        assertTrue(paths.configFile.readText(StandardCharsets.UTF_8).contains("MODE"))
        assertTrue(paths.sniListFile.readText(StandardCharsets.UTF_8).isNotBlank())
        assertTrue(paths.ipListFile.readText(StandardCharsets.UTF_8).isNotBlank())
        assertTrue(status.successful)
        assertEquals(ProfileUpdateMode.Manual, status.mode)
    }

    private fun repository(clock: () -> Long): ProfileRepository =
        ProfileRepository(
            context = context,
            clock = clock,
            idGenerator = { "profile-${System.nanoTime()}" },
        )

    private fun sequenceClock(vararg values: Long): () -> Long {
        val iterator = values.iterator()
        var last = values.lastOrNull() ?: 0L
        return {
            if (iterator.hasNext()) {
                last = iterator.nextLong()
            }
            last
        }
    }

    private fun fakeClient(
        remote: ProfileRemoteSettings,
        files: ProfileUpdateFileContents,
        failures: Map<ProfileRemoteFile, String> = emptyMap(),
    ): ProfileRemoteClient =
        object : ProfileRemoteClient {
            override suspend fun download(
                file: ProfileRemoteFile,
                url: String,
            ): ProfileRemoteFileResult =
                failures[file]?.let { error ->
                    ProfileRemoteFileResult(
                        file = file,
                        requestedUrl = url,
                        errorMessage = error,
                    )
                } ?: ProfileRemoteFileResult(
                    file = file,
                    requestedUrl = file.urlFrom(remote),
                    contentText = when (file) {
                        ProfileRemoteFile.Config -> files.configText
                        ProfileRemoteFile.SniList -> files.sniListText
                        ProfileRemoteFile.IpList -> files.ipListText
                    },
                )
        }

    private fun remoteSettings(): ProfileRemoteSettings =
        ProfileRemoteSettings(
            configUrl = "https://example.com/zerodpi/config.toml",
            sniListUrl = "https://example.com/zerodpi/sni_list.txt",
            ipListUrl = "https://example.com/zerodpi/ip_list.txt",
        )

    private fun githubRawRemoteSettings(): ProfileRemoteSettings {
        val baseUrl = "https://raw.githubusercontent.com/nullroute1970/ZeroDPI/master/" +
            "android/app/src/main/assets/zerodpi"
        return ProfileRemoteSettings(
            configUrl = "$baseUrl/config.toml",
            sniListUrl = "$baseUrl/sni_list.txt",
            ipListUrl = "$baseUrl/ip_list.txt",
        )
    }

    private fun remoteUrlsReachable(remote: ProfileRemoteSettings): Boolean =
        listOf(remote.configUrl, remote.sniListUrl, remote.ipListUrl).all { url ->
            runCatching {
                val connection = URL(url).openConnection() as HttpURLConnection
                try {
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = 5_000
                    connection.readTimeout = 5_000
                    connection.requestMethod = "HEAD"
                    connection.responseCode in 200..299
                } finally {
                    connection.disconnect()
                }
            }.getOrDefault(false)
        }

    private fun profileFileTexts(paths: ProfileFilePaths): Map<RuntimeFileKind, String> =
        RuntimeFileKind.entries.associateWith { kind ->
            paths.fileFor(kind).readText(StandardCharsets.UTF_8)
        }

    private fun assetText(kind: RuntimeFileKind): String =
        context.assets.open("zerodpi/${kind.fileName}").use { input ->
            input.bufferedReader(StandardCharsets.UTF_8).readText()
        }

    private fun runtimeDir(): File =
        File(context.filesDir, "zerodpi")

    private fun clearRuntimeDir() {
        runtimeDir().deleteRecursively()
    }
}
