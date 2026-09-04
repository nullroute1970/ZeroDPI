package dev.zerodpi.android.ui

import android.app.Application
import android.content.Context
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.profile.ProfileRemoteClient
import dev.zerodpi.android.profile.ProfileRemoteFile
import dev.zerodpi.android.profile.ProfileRemoteFileResult
import dev.zerodpi.android.profile.ProfileRemoteSettings
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.profile.ProfileUpdateFileContents
import dev.zerodpi.android.profile.ProfileUpdateManager
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.service.RootStatus
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.storage.RuntimeStorage
import dev.zerodpi.android.storage.TargetPinStore
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.TargetPin
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
class MainViewModelInstrumentedTest {
    private lateinit var application: Application
    private lateinit var context: Context

    @Before
    fun setUp() {
        application = ApplicationProvider.getApplicationContext()
        context = application.applicationContext
        clearRuntimeDir()
    }

    @After
    fun tearDown() {
        clearRuntimeDir()
    }

    @Test
    fun stoppedDashboardSummaryFollowsLoadedConfig() = runBlocking {
        val viewModel = viewModel()
        viewModel.waitUntilLoaded()

        val state = viewModel.uiState.value

        assertEquals(RootStatus.Needed, state.rootStatus)
        assertEquals("sni_spoof", state.mode)
        assertEquals("wrong_seq + tls_frag", state.bypassMethod)
        assertEquals("127.0.0.1:44444", state.listener)
    }

    @Test
    fun stoppedDashboardSummaryFollowsConfigEdits() = runBlocking {
        val viewModel = viewModel()
        viewModel.waitUntilLoaded()

        viewModel.updateConfigField("BYPASS_METHOD", "tls_frag")
        viewModel.updateConfigField("LISTEN_PORT", "1080")

        val state = viewModel.uiState.value

        assertEquals(RootStatus.NotNeeded, state.rootStatus)
        assertEquals("sni_spoof", state.mode)
        assertEquals("tls_frag", state.bypassMethod)
        assertEquals("127.0.0.1:1080", state.listener)
    }

    @Test
    fun autoSaveProfileASwitchToProfileBAndProfileAContentRemains() = runBlocking {
        val repository = repository(generatedIds = listOf("profile-b"))
        val viewModel = viewModel(repository = repository)
        viewModel.waitUntilLoaded()
        val profileAConfig = viewModel.runtimeFilesState.value.configText
            .replaceField("LISTEN_PORT", "41111")

        viewModel.updateRuntimeFileText(RuntimeFileKind.Config, profileAConfig)
        viewModel.waitUntil("automatic config save") {
            RuntimeFileKind.Config !in runtimeFilesState.value.dirtyFiles &&
                runtimeFilesState.value.statusMessage?.contains("Saved config.toml automatically") == true
        }
        viewModel.createProfileFromDefaults("Profile B")
        viewModel.waitUntil("profile-b creation") {
            profileState.value.profiles.any { it.id == "profile-b" } &&
                !profileState.value.isProfileLoading
        }

        viewModel.selectProfile("profile-b")
        viewModel.waitUntil("profile-b selected") {
            runtimeFilesState.value.activeProfileId == "profile-b" &&
                !runtimeFilesState.value.isLoading
        }

        val storage = RuntimeStorage(context)
        val profileA = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        val profileB = storage.readAll("profile-b")
        assertEquals("41111", ZeroDpiConfigToml.analyze(profileA.configText).valueFor("LISTEN_PORT"))
        assertFalse(profileB.configText.contains("41111"))
    }

    @Test
    fun autoSaveAndReopenAppWithMultipleProfiles() = runBlocking {
        val repository = repository(generatedIds = listOf("profile-b"))
        val viewModel = viewModel(repository = repository)
        viewModel.waitUntilLoaded()

        viewModel.createProfileFromDefaults("Profile B")
        viewModel.waitUntil("profile-b creation") {
            profileState.value.profiles.any { it.id == "profile-b" } &&
                !profileState.value.isProfileLoading
        }
        viewModel.selectProfile("profile-b")
        viewModel.waitUntil("profile-b selected") {
            runtimeFilesState.value.activeProfileId == "profile-b" &&
                !runtimeFilesState.value.isLoading
        }
        viewModel.updateRuntimeFileText(RuntimeFileKind.SniList, "persisted-profile-b.example\n")
        viewModel.waitUntil("automatic sni list save") {
            RuntimeFileKind.SniList !in runtimeFilesState.value.dirtyFiles &&
                runtimeFilesState.value.statusMessage?.contains("Saved sni_list.txt automatically") == true
        }

        val reopened = viewModel(repository = repository())
        reopened.waitUntilLoaded()

        assertEquals("profile-b", reopened.runtimeFilesState.value.activeProfileId)
        assertEquals(
            listOf(ZeroDpiProfile.DEFAULT_PROFILE_NAME, "Profile B"),
            reopened.profileState.value.profiles.map { it.name },
        )
        assertEquals("persisted-profile-b.example\n", reopened.runtimeFilesState.value.sniListText)
    }

    @Test
    fun manualUpdateReloadsEditorContentAndClearsDirtyFlags() {
        val repository = repository(clock = sequenceClock(1000L, 2000L, 3000L))
        val remote = remoteSettings()
        val remoteFiles = ProfileUpdateFileContents(
            configText = assetText(RuntimeFileKind.Config).replaceField("LISTEN_PORT", "48888"),
            sniListText = "remote-update.example\n",
            ipListText = "203.0.113.20\n",
        )
        val viewModel = viewModel(
            repository = repository,
            profileUpdateManager = ProfileUpdateManager(
                profileRepository = repository,
                remoteClient = StaticRemoteClient(remoteFiles),
            ),
        )
        viewModel.waitUntilLoaded()
        viewModel.updateActiveProfileRemoteSettings(remote)
        viewModel.waitUntil("remote settings save") {
            !profileState.value.hasUnsavedProfileRemoteSettings &&
                profileState.value.profileRemoteSettings.configUrl == remote.configUrl &&
                !profileState.value.isProfileLoading
        }
        viewModel.updateRuntimeFileText(RuntimeFileKind.SniList, "unsaved-local.example\n")
        viewModel.waitUntil("dirty sni list") {
            RuntimeFileKind.SniList in runtimeFilesState.value.dirtyFiles
        }

        viewModel.updateActiveProfileFromRemote()
        viewModel.waitUntil("manual remote update") {
            !profileState.value.isRemoteUpdating &&
                runtimeFilesState.value.sniListText == remoteFiles.sniListText
        }

        assertTrue(viewModel.runtimeFilesState.value.dirtyFiles.isEmpty())
        assertEquals(remoteFiles.ipListText, viewModel.runtimeFilesState.value.ipListText)
        assertEquals(
            "48888",
            viewModel.runtimeFilesState.value.configEditor.valueFor("LISTEN_PORT"),
        )
        assertEquals("Updated profile from remote.", viewModel.profileState.value.statusMessage)
    }

    @Test
    fun profileSwitchFlushesPendingAutoSave() = runBlocking {
        val repository = repository(generatedIds = listOf("profile-b"))
        val viewModel = viewModel(repository = repository)
        viewModel.waitUntilLoaded()
        viewModel.createProfileFromDefaults("Profile B")
        viewModel.waitUntil("profile-b creation") {
            profileState.value.profiles.any { it.id == "profile-b" } &&
                !profileState.value.isProfileLoading
        }

        val dirtyConfig = viewModel.runtimeFilesState.value.configText
            .replaceField("LISTEN_PORT", "49999")
        viewModel.updateRuntimeFileText(RuntimeFileKind.Config, dirtyConfig)
        viewModel.selectProfile("profile-b")
        viewModel.waitUntil("automatically saved profile switch") {
            runtimeFilesState.value.activeProfileId == "profile-b" &&
                runtimeFilesState.value.dirtyFiles.isEmpty() &&
                !profileState.value.isProfileSwitching
        }

        val profileA = RuntimeStorage(context).readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        assertEquals("49999", ZeroDpiConfigToml.analyze(profileA.configText).valueFor("LISTEN_PORT"))
        assertEquals("Saved changes and switched profile.", viewModel.profileState.value.statusMessage)
    }

    private fun viewModel(
        repository: ProfileRepository = repository(),
        profileUpdateManager: ProfileUpdateManager = ProfileUpdateManager(repository),
    ): MainViewModel =
        MainViewModel(
            application = application,
            profileRepository = repository,
            runtimeStorage = RuntimeStorage(context),
            profileUpdateManager = profileUpdateManager,
            autoUpdateReconciler = { _, _ -> },
            bindServiceOnInit = false,
        )

    private fun MainViewModel.waitUntilLoaded() {
        waitUntil("runtime files loaded") {
            !runtimeFilesState.value.isLoading && !profileState.value.isProfileLoading
        }
    }

    private fun MainViewModel.waitUntil(
        description: String,
        timeoutMs: Long = 5_000L,
        predicate: MainViewModel.() -> Boolean,
    ) {
        val deadline = SystemClock.uptimeMillis() + timeoutMs
        while (SystemClock.uptimeMillis() < deadline) {
            if (predicate()) {
                return
            }
            Thread.sleep(25)
        }
        fail(
            "Timed out waiting for $description. " +
                "profile=${profileState.value}; runtime=${runtimeFilesState.value}",
        )
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

    private fun remoteSettings(): ProfileRemoteSettings =
        ProfileRemoteSettings(
            configUrl = "https://example.com/zerodpi/config.toml",
            sniListUrl = "https://example.com/zerodpi/sni_list.txt",
            ipListUrl = "https://example.com/zerodpi/ip_list.txt",
        )

    private class StaticRemoteClient(
        private val files: ProfileUpdateFileContents,
    ) : ProfileRemoteClient {
        override suspend fun download(
            file: ProfileRemoteFile,
            url: String,
        ): ProfileRemoteFileResult =
            ProfileRemoteFileResult(
                file = file,
                requestedUrl = url,
                contentText = when (file) {
                    ProfileRemoteFile.Config -> files.configText
                    ProfileRemoteFile.SniList -> files.sniListText
                    ProfileRemoteFile.IpList -> files.ipListText
                },
            )
    }

    private fun String.replaceField(fieldName: String, value: String): String =
        ZeroDpiConfigToml.replaceOrAppendField(this, fieldName, value)

    private fun assetText(kind: RuntimeFileKind): String =
        context.assets.open("zerodpi/${kind.fileName}").use { input ->
            input.bufferedReader(StandardCharsets.UTF_8).readText()
        }

    private fun clearRuntimeDir() {
        File(context.filesDir, "zerodpi").deleteRecursively()
    }

    @Test
    fun startGateWithAutoSelectOffShowsPickerAndPickPinsAndRuns() = runBlocking {
        val viewModel = viewModel()
        viewModel.waitUntilLoaded()
        viewModel.updateConfigField("AUTO_SELECT", "false")
        viewModel.waitUntil("auto-select config saved") {
            RuntimeFileKind.Config !in runtimeFilesState.value.dirtyFiles &&
                runtimeFilesState.value.configEditor.valueFor("AUTO_SELECT") == "false"
        }

        viewModel.start()

        viewModel.waitUntil("picker choosing with results", timeoutMs = 15_000L) {
            viewModel.targetPickState.value.phase == TargetPickPhase.Choosing &&
                viewModel.targetPickState.value.entries != null
        }
        val entries = viewModel.targetPickState.value.entries
        assertEquals(2, entries?.size)
        val best = entries?.first { it.score > 0 }
        assertEquals("cloudflare.com", best?.sni)

        viewModel.chooseTarget(best!!)

        viewModel.waitUntil("running after pick", timeoutMs = 15_000L) {
            uiState.value.status == RuntimeStatus.Running && uiState.value.pickSession == null
        }
        // Pin persisted app-side.
        val pin = TargetPinStore(context).read(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        assertEquals("cloudflare.com", pin?.sni)
        assertEquals(PinKind.Sni, pin?.kind)

        viewModel.stop()
        viewModel.waitUntil("stopped after pick run") {
            uiState.value.status == RuntimeStatus.Stopped
        }
    }

    @Test
    fun clearTargetPinClearsStoredPin() = runBlocking {
        val viewModel = viewModel()
        viewModel.waitUntilLoaded()
        TargetPinStore(context).write(
            ZeroDpiProfile.DEFAULT_PROFILE_ID,
            TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L),
        )
        viewModel.refreshTargetPin()
        viewModel.waitUntil("pin shown") { targetPickState.value.pin?.sni == "cloudflare.com" }

        viewModel.clearTargetPin()

        viewModel.waitUntil("pin cleared") { targetPickState.value.pin == null }
    }
}
