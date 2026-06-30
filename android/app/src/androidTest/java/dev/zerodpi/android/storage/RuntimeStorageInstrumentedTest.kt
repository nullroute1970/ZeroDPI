package dev.zerodpi.android.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.profile.ZeroDpiProfile
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class RuntimeStorageInstrumentedTest {
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
    fun settingsAndListsSaveAndReopenFromAppPrivateStorage() = runBlocking {
        val storage = RuntimeStorage(context)
        val defaults = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        val config = defaults.configText
            .replaceField("LISTEN_PORT", "45678")
            .replaceField("MODE", "sni_spoof")
            .replaceField("BYPASS_METHOD", "tls_frag")
        val sniList = "# preserved comment\ncloudflare.com\n"
        val ipList = "# preserved comment\n1.1.1.1\n2606:4700::6810:84e5\n"

        storage.saveAll(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            configText = config,
            sniListText = sniList,
            ipListText = ipList,
        )
        val reopened = RuntimeStorage(context).readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID)

        assertEquals(config, reopened.configText)
        assertEquals(sniList, reopened.sniListText)
        assertEquals(ipList, reopened.ipListText)
        assertTrue(reopened.files.configFile.isFile)
        assertTrue(File(reopened.files.runtimeDir, "config.toml.bak").isFile)
    }

    @Test
    fun testScanModeOverrideCreatesTemporaryConfigWithoutChangingStoredConfig() = runBlocking {
        val storage = RuntimeStorage(context)
        val storedConfig = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText
            .replaceField("MODE", "sni_spoof")
            .replaceField("BYPASS_METHOD", "tls_frag")
        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, storedConfig)

        val runConfig = storage.prepareRunConfig(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            modeOverride = "ip_scan",
        )
        val reopened = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID)

        assertTrue(runConfig.configFile.name.contains("ip_scan"))
        assertEquals(runConfig.files.runtimeDir, runConfig.configFile.parentFile)
        assertEquals("ip_scan", ZeroDpiConfigToml.analyze(runConfig.configText).valueFor("MODE"))
        assertEquals("sni_spoof", ZeroDpiConfigToml.analyze(reopened.configText).valueFor("MODE"))
    }

    @Test
    fun readsAndWritesOnlySelectedProfile() = runBlocking {
        val storage = RuntimeStorage(context)
        val repository = ProfileRepository(context, idGenerator = { "second" })
        val secondProfile = repository.createProfile("Second").profiles.first { it.id == "second" }
        val defaultConfig = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText
            .replaceField("LISTEN_PORT", "11111")
        val secondConfig = storage.readAll(secondProfile.id).configText
            .replaceField("LISTEN_PORT", "22222")

        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, defaultConfig)
        storage.save(secondProfile.id, RuntimeFileKind.Config, secondConfig)
        storage.save(secondProfile.id, RuntimeFileKind.SniList, "profile-two.example\n")

        val defaultReopened = RuntimeStorage(context).readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        val secondReopened = RuntimeStorage(context).readAll(secondProfile.id)

        assertEquals("11111", ZeroDpiConfigToml.analyze(defaultReopened.configText).valueFor("LISTEN_PORT"))
        assertEquals("22222", ZeroDpiConfigToml.analyze(secondReopened.configText).valueFor("LISTEN_PORT"))
        assertEquals("profile-two.example\n", secondReopened.sniListText)
        assertTrue(defaultReopened.files.runtimeDir.absolutePath.endsWith("/profiles/default"))
        assertTrue(secondReopened.files.runtimeDir.absolutePath.endsWith("/profiles/second"))
    }

    @Test
    fun relativeConfigPathsResolveInsideSelectedProfileDirectory() = runBlocking {
        val storage = RuntimeStorage(context)
        val profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID
        val config = storage.readAll(profileId).configText
            .replaceField("SNI_LIST", "lists/sni_list.txt")
            .replaceField("IP_LIST", "lists/ip_list.txt")
            .replaceField("SCAN_OUTPUT", "scan_results/results.txt")

        storage.save(profileId, RuntimeFileKind.Config, config)

        val files = storage.readAll(profileId).files
        val resolved = storage.prepareConfiguredDirectories(profileId)

        assertEquals(File(files.runtimeDir, "lists/sni_list.txt"), resolved.sniList)
        assertEquals(File(files.runtimeDir, "lists/ip_list.txt"), resolved.ipList)
        assertEquals(File(files.runtimeDir, "scan_results/results.txt"), resolved.scanOutput)
        assertTrue(resolved.scanOutput?.parentFile?.isDirectory == true)
    }

    private fun String.replaceField(fieldName: String, value: String): String =
        ZeroDpiConfigToml.replaceOrAppendField(this, fieldName, value)

    private fun clearRuntimeDir() {
        File(context.filesDir, "zerodpi").deleteRecursively()
    }
}
