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
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets

@RunWith(AndroidJUnit4::class)
class ProfileRepositoryInstrumentedTest {
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
    fun migratesLegacyRuntimeFilesIntoDefaultProfileAndLeavesLegacyFiles() = runBlocking {
        val runtimeDir = runtimeDir()
        runtimeDir.mkdirs()
        val legacyConfig = "MODE = \"sni_spoof\"\nSNI_LIST = \"sni_list.txt\"\nIP_LIST = \"ip_list.txt\"\n"
        val legacySni = "legacy.example.com\n"
        val legacyIp = "203.0.113.10\n"
        File(runtimeDir, RuntimeFileKind.Config.fileName).writeText(legacyConfig, StandardCharsets.UTF_8)
        File(runtimeDir, RuntimeFileKind.SniList.fileName).writeText(legacySni, StandardCharsets.UTF_8)
        File(runtimeDir, RuntimeFileKind.IpList.fileName).writeText(legacyIp, StandardCharsets.UTF_8)

        val index = repository(clock = { 1234L }).loadIndex()
        val paths = repository().filePaths(ZeroDpiProfile.DEFAULT_PROFILE_ID)

        assertEquals(ZeroDpiProfile.DEFAULT_PROFILE_ID, index.activeProfileId)
        assertEquals(listOf(ZeroDpiProfile.DEFAULT_PROFILE_NAME), index.profiles.map { it.name })
        assertEquals(legacyConfig, paths.configFile.readText(StandardCharsets.UTF_8))
        assertEquals(legacySni, paths.sniListFile.readText(StandardCharsets.UTF_8))
        assertEquals(legacyIp, paths.ipListFile.readText(StandardCharsets.UTF_8))
        assertEquals(legacyConfig, File(runtimeDir, RuntimeFileKind.Config.fileName).readText(StandardCharsets.UTF_8))
        assertTrue(ProfilePaths.indexFile(runtimeDir).isFile)
    }

    @Test
    fun freshInstallSeedsDefaultProfileFromAssets() = runBlocking {
        val index = repository(clock = { 2000L }).loadIndex()
        val paths = repository().activeFilePaths()

        assertEquals(ZeroDpiProfile.DEFAULT_PROFILE_ID, index.activeProfileId)
        assertEquals(2000L, index.profiles.single().createdAtEpochMs)
        assertEquals(assetText(RuntimeFileKind.Config), paths.configFile.readText(StandardCharsets.UTF_8))
        assertEquals(assetText(RuntimeFileKind.SniList), paths.sniListFile.readText(StandardCharsets.UTF_8))
        assertEquals(assetText(RuntimeFileKind.IpList), paths.ipListFile.readText(StandardCharsets.UTF_8))
        assertTrue(paths.scanResultsDir.isDirectory)
    }

    @Test
    fun profileCrudAndSelectionPersistAcrossRepositoryInstances() = runBlocking {
        val repository = repository(
            generatedIds = listOf("work", "work-copy"),
            clock = sequenceClock(10L, 20L, 30L, 40L),
        )

        repository.loadIndex()
        var index = repository.createProfile("Work")
        assertEquals(2, index.profiles.size)
        assertEquals(ZeroDpiProfile.DEFAULT_PROFILE_ID, index.activeProfileId)

        val workPaths = repository.filePaths("work")
        val customConfig = "MODE = \"ip_scan\"\nSNI_LIST = \"sni_list.txt\"\nIP_LIST = \"ip_list.txt\"\n"
        workPaths.configFile.writeText(customConfig, StandardCharsets.UTF_8)

        index = repository.renameProfile("work", "Office")
        assertEquals("Office", index.profiles.first { it.id == "work" }.name)

        index = repository.duplicateProfile(sourceProfileId = "work", name = "Office Copy")
        val copyPaths = repository.filePaths("work-copy")
        assertEquals(customConfig, copyPaths.configFile.readText(StandardCharsets.UTF_8))
        assertEquals(3, index.profiles.size)

        index = repository.selectProfile("work-copy")
        assertEquals("work-copy", index.activeProfileId)

        index = repository.deleteProfile("work-copy")
        assertEquals(ZeroDpiProfile.DEFAULT_PROFILE_ID, index.activeProfileId)
        assertFalse(copyPaths.profileDir.exists())

        val reopened = repository().loadIndex()
        assertEquals(index, reopened)
    }

    @Test
    fun corruptedIndexReportsRecoverableErrorAndKeepsProfileFiles() = runBlocking {
        val repository = repository()
        repository.loadIndex()
        val defaultProfileDir = File(File(runtimeDir(), ProfilePaths.PROFILES_DIR_NAME), ZeroDpiProfile.DEFAULT_PROFILE_ID)
        val configFile = File(defaultProfileDir, RuntimeFileKind.Config.fileName)
        val preservedConfig = "MODE = \"sni_spoof\"\n"
        configFile.writeText(preservedConfig, StandardCharsets.UTF_8)
        ProfilePaths.indexFile(runtimeDir()).writeText("{not json", StandardCharsets.UTF_8)

        try {
            repository.loadIndex()
            fail("Expected corrupt profile index to fail.")
        } catch (expected: ProfileRepositoryException) {
            assertTrue(expected.message.orEmpty().contains("unreadable"))
        }

        assertTrue(defaultProfileDir.isDirectory)
        assertEquals(preservedConfig, configFile.readText(StandardCharsets.UTF_8))
    }

    private fun repository(
        generatedIds: List<String> = emptyList(),
        clock: () -> Long = { 1000L },
    ): ProfileRepository {
        val ids = generatedIds.iterator()
        return ProfileRepository(
            context = context,
            clock = clock,
            idGenerator = {
                if (ids.hasNext()) {
                    ids.next()
                } else {
                    "profile-${System.nanoTime()}"
                }
            },
        )
    }

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
