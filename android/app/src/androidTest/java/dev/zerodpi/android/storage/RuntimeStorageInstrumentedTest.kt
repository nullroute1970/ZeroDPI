package dev.zerodpi.android.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zerodpi.android.config.ZeroDpiConfigToml
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
        val defaults = storage.readAll()
        val config = defaults.configText
            .replaceField("LISTEN_PORT", "45678")
            .replaceField("MODE", "sni_spoof")
            .replaceField("BYPASS_METHOD", "tls_frag")
        val sniList = "# preserved comment\ncloudflare.com\n"
        val ipList = "# preserved comment\n1.1.1.1\n2606:4700::6810:84e5\n"

        storage.saveAll(
            configText = config,
            sniListText = sniList,
            ipListText = ipList,
        )
        val reopened = RuntimeStorage(context).readAll()

        assertEquals(config, reopened.configText)
        assertEquals(sniList, reopened.sniListText)
        assertEquals(ipList, reopened.ipListText)
        assertTrue(reopened.files.configFile.isFile)
        assertTrue(File(reopened.files.runtimeDir, "config.toml.bak").isFile)
    }

    @Test
    fun testScanModeOverrideCreatesTemporaryConfigWithoutChangingStoredConfig() = runBlocking {
        val storage = RuntimeStorage(context)
        val storedConfig = storage.readAll().configText
            .replaceField("MODE", "sni_spoof")
            .replaceField("BYPASS_METHOD", "tls_frag")
        storage.save(RuntimeFileKind.Config, storedConfig)

        val runConfig = storage.prepareRunConfig(modeOverride = "ip_scan")
        val reopened = storage.readAll()

        assertTrue(runConfig.configFile.name.contains("ip_scan"))
        assertEquals("ip_scan", ZeroDpiConfigToml.analyze(runConfig.configText).valueFor("MODE"))
        assertEquals("sni_spoof", ZeroDpiConfigToml.analyze(reopened.configText).valueFor("MODE"))
    }

    private fun String.replaceField(fieldName: String, value: String): String =
        ZeroDpiConfigToml.replaceOrAppendField(this, fieldName, value)

    private fun clearRuntimeDir() {
        File(context.filesDir, "zerodpi").deleteRecursively()
    }
}
