package dev.zerodpi.android.profile

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.work.Configuration
import androidx.work.ListenableWorker
import androidx.work.testing.TestListenableWorkerBuilder
import androidx.work.testing.WorkManagerTestInitHelper
import dev.zerodpi.android.service.ZeroDpiRuntimeStateStore
import dev.zerodpi.android.storage.RuntimeFileKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
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
class ProfileAutoUpdateWorkerInstrumentedTest {
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        clearRuntimeDir()
        ZeroDpiRuntimeStateStore.markRuntimeInactive(context)
        WorkManagerTestInitHelper.initializeTestWorkManager(
            context,
            Configuration.Builder().build(),
        )
    }

    @After
    fun tearDown() {
        ZeroDpiRuntimeStateStore.markRuntimeInactive(context)
        clearRuntimeDir()
    }

    @Test
    fun automaticWorkerUpdatesDueProfileFromRealHttpsUrls() = runBlocking {
        val remote = githubRawRemoteSettings(autoUpdateEnabled = true)
        assumeTrue("GitHub raw HTTPS runtime assets are not reachable.", remoteUrlsReachable(remote))
        val repository = ProfileRepository(context)
        repository.loadIndex()
        repository.updateRemoteSettings(ZeroDpiProfile.DEFAULT_PROFILE_ID, remote)

        val result = worker().doWork()
        val updatedProfile = repository.loadIndex().profiles.single()
        val paths = repository.activeFilePaths()

        assertEquals(ListenableWorker.Result.success(), result)
        assertNotNull(updatedProfile.remote.lastSuccessfulUpdateEpochMs)
        assertTrue(updatedProfile.remote.lastUpdateStatus?.successful == true)
        assertEquals(ProfileUpdateMode.Automatic, updatedProfile.remote.lastUpdateStatus?.mode)
        assertTrue(paths.configFile.readText(StandardCharsets.UTF_8).contains("MODE"))
        assertTrue(paths.sniListFile.readText(StandardCharsets.UTF_8).isNotBlank())
        assertTrue(paths.ipListFile.readText(StandardCharsets.UTF_8).isNotBlank())
    }

    @Test
    fun automaticWorkerDefersDueProfileWhileRuntimeIsRunning() = runBlocking {
        val repository = ProfileRepository(context)
        repository.loadIndex()
        repository.updateRemoteSettings(
            ZeroDpiProfile.DEFAULT_PROFILE_ID,
            githubRawRemoteSettings(autoUpdateEnabled = true),
        )
        val paths = repository.activeFilePaths()
        val oldFiles = RuntimeFileKind.entries.associateWith { kind ->
            paths.fileFor(kind).readText(StandardCharsets.UTF_8)
        }
        ZeroDpiRuntimeStateStore.markRuntimeActive(context, profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID)

        val result = worker().doWork()
        val updatedProfile = repository.loadIndex().profiles.single()
        val status = updatedProfile.remote.lastUpdateStatus

        assertEquals(ListenableWorker.Result.success(), result)
        assertFalse(status?.successful == true)
        assertEquals(ProfileUpdateMode.Automatic, status?.mode)
        assertTrue(status?.message.orEmpty().contains("ZeroDPI is running"))
        assertEquals(
            oldFiles,
            RuntimeFileKind.entries.associateWith { kind ->
                paths.fileFor(kind).readText(StandardCharsets.UTF_8)
            },
        )
    }

    private fun worker(): ProfileAutoUpdateWorker =
        TestListenableWorkerBuilder<ProfileAutoUpdateWorker>(context).build()

    private fun githubRawRemoteSettings(autoUpdateEnabled: Boolean): ProfileRemoteSettings {
        val baseUrl = "https://raw.githubusercontent.com/nullroute1970/ZeroDPI/master/" +
            "android/app/src/main/assets/zerodpi"
        return ProfileRemoteSettings(
            configUrl = "$baseUrl/config.toml",
            sniListUrl = "$baseUrl/sni_list.txt",
            ipListUrl = "$baseUrl/ip_list.txt",
            autoUpdateEnabled = autoUpdateEnabled,
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

    private fun clearRuntimeDir() {
        File(context.filesDir, "zerodpi").deleteRecursively()
    }
}
