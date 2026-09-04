package dev.zerodpi.android.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.TargetPin
import dev.zerodpi.android.targetscan.TargetScanFiles
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets

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

    @Test
    fun clearLogsDeletesStoredSessionsAndAllowsFreshOutput() = runBlocking {
        val storage = RuntimeStorage(context)
        val files = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).files
        storage.startNewLogSession("first")
        storage.appendLogLine("old entry")
        storage.startNewLogSession("second")
        storage.appendLogLine("another old entry")

        assertTrue(files.logsDir.listFiles().orEmpty().count { it.extension == "log" } >= 2)

        storage.clearLogs()

        assertTrue(files.logsDir.listFiles().orEmpty().none { it.extension == "log" })

        storage.appendLogLine("fresh entry")
        val freshLogs = files.logsDir.listFiles().orEmpty().filter { it.extension == "log" }
        assertEquals(1, freshLogs.size)
        assertTrue(freshLogs.single().readText().contains("fresh entry"))
    }

    @Test
    fun resolvesAndReadsMethodScanOutput() = runBlocking {
        val storage = RuntimeStorage(context)
        val profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID
        val configText = """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_method_scan"
            METHOD_SCAN_OUTPUT = "method_scan_output.json"
        """.trimIndent()
        storage.save(profileId, RuntimeFileKind.Config, configText)
        val runtimeDir = storage.readAll(profileId).files.runtimeDir
        val paths = storage.resolveConfigPaths(configText, runtimeDir)
        assertNotNull(paths.methodScanOutput)
        assertEquals("method_scan_output.json", paths.methodScanOutput?.name)

        assertNull(storage.readMethodScanOutput(profileId, configText)) // null: file not written yet
        val target = paths.methodScanOutput!!
        target.parentFile?.mkdirs()
        target.writeText("""{"mode":"sni_method_scan"}""")
        assertEquals("""{"mode":"sni_method_scan"}""", storage.readMethodScanOutput(profileId, configText))
    }

    @Test
    fun pickScanConfigPatchesModeAndScanOutputIntoEphemeralFile() = runBlocking {
        val storage = RuntimeStorage(context)
        val files = storage.ensureInitialized(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        val stored = files.configFile.readText(StandardCharsets.UTF_8)
        val run = storage.prepareRunConfig(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            modeOverride = "sni_scan",
            patchFields = mapOf("SCAN_OUTPUT" to TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME),
        )
        assertTrue(run.configFile.name.startsWith(".sni_scan_config.toml"))
        assertTrue(run.configText.contains("MODE = \"sni_scan\""))
        assertTrue(run.configText.contains("SCAN_OUTPUT = \"pick_scan_results.json\""))
        // The user's config file is untouched.
        assertEquals(stored, files.configFile.readText(StandardCharsets.UTF_8))
    }

    @Test
    fun pinInjectionAddsSelectedSniAndSkipsScanOverrides() = runBlocking {
        val storage = RuntimeStorage(context)
        val pin = TargetPin(PinKind.Sni, "edge.example.com", "1.2.3.4", 95, 1L)
        val plain = storage.prepareRunConfig(profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID)
        assertFalse(plain.configText.contains("edge.example.com"))
        // modeOverride runs never inject a pin.
        val scanRun = storage.prepareRunConfig(
            profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
            modeOverride = "sni_scan",
            pin = pin,
        )
        assertFalse(scanRun.configText.contains("edge.example.com"))
        // Real run with matching pin -> ephemeral config with SELECTED_SNI.
        val pinned = storage.prepareRunConfig(profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID, pin = pin)
        assertTrue(pinned.configFile.name == ".run_config.toml")
        assertTrue(pinned.configText.contains("SELECTED_SNI = \"edge.example.com\""))
        // Real run with mismatched kind -> no injection.
        val ipPin = TargetPin(PinKind.Ip, null, "5.6.7.8", 96, 1L)
        val mismatched = storage.prepareRunConfig(profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID, pin = ipPin)
        assertFalse(mismatched.configText.contains("edge.example.com"))
    }

    @Test
    fun pinInjectionDefersToManualSelectedSni() = runBlocking {
        val storage = RuntimeStorage(context)
        val manual = ZeroDpiConfigToml.replaceOrAppendField(
            storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText,
            "SELECTED_SNI",
            "manual.example",
        )
        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, manual)
        val pin = TargetPin(PinKind.Sni, "edge.example.com", "1.2.3.4", 95, 1L)
        val run = storage.prepareRunConfig(profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID, pin = pin)
        assertTrue(run.configText.contains("SELECTED_SNI = \"manual.example\""))
        assertFalse(run.configText.contains("edge.example.com"))
    }

    @Test
    fun pickScanResultsWriteReadDeleteLifecycle() = runBlocking {
        val storage = RuntimeStorage(context)
        val profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID
        storage.deletePickScanResults(profileId)
        assertNull(storage.readPickScanResults(profileId))
        val files = storage.ensureInitialized(profileId)
        val resultsFile = File(files.runtimeDir, TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME)
        resultsFile.writeText("[]")
        assertEquals("[]", storage.readPickScanResults(profileId))
        storage.deletePickScanResults(profileId)
        assertNull(storage.readPickScanResults(profileId))
    }

    private fun String.replaceField(fieldName: String, value: String): String =
        ZeroDpiConfigToml.replaceOrAppendField(this, fieldName, value)

    private fun clearRuntimeDir() {
        File(context.filesDir, "zerodpi").deleteRecursively()
    }
}
