package dev.zerodpi.android.ui

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.zerodpi.android.config.ConfigEditorState
import dev.zerodpi.android.config.ZeroDpiConfigSchema
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.diagnostics.AndroidDiagnosticsProvider
import dev.zerodpi.android.diagnostics.DeviceDiagnostics
import dev.zerodpi.android.list.RuntimeListIssue
import dev.zerodpi.android.list.RuntimeListValidation
import dev.zerodpi.android.list.RuntimeListValidator
import dev.zerodpi.android.methodscan.MethodScanReportModel
import dev.zerodpi.android.methodscan.MethodScanReportParser
import dev.zerodpi.android.profile.ProfileAutoUpdateScheduler
import dev.zerodpi.android.profile.ProfileIndex
import dev.zerodpi.android.profile.ProfileRemoteSettings
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.profile.ProfileUpdateManager
import dev.zerodpi.android.profile.ProfileUpdateMode
import dev.zerodpi.android.profile.ProfileUpdateResult
import dev.zerodpi.android.profile.ProfileUpdater
import dev.zerodpi.android.profile.ProfileValidationResult
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.service.PickOrigin
import dev.zerodpi.android.service.PickPhase
import dev.zerodpi.android.service.RootStatus
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ScanProgressInfo
import dev.zerodpi.android.service.ZeroDpiRuntimeStateStore
import dev.zerodpi.android.service.ZeroDpiService
import dev.zerodpi.android.service.ZeroDpiServiceState
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.storage.RuntimeStorage
import dev.zerodpi.android.storage.TargetPinStore
import dev.zerodpi.android.targetscan.IpScanEntryModel
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.ScanResultParser
import dev.zerodpi.android.targetscan.SniScanEntryModel
import dev.zerodpi.android.targetscan.TargetPickPolicy
import dev.zerodpi.android.targetscan.TargetPin
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.OutputStream

data class RuntimeFilesUiState(
    val selectedFile: RuntimeFileKind = RuntimeFileKind.Config,
    val activeProfileId: String = ZeroDpiProfile.DEFAULT_PROFILE_ID,
    val activeProfileName: String = ZeroDpiProfile.DEFAULT_PROFILE_NAME,
    val runtimeDir: String = "",
    val configText: String = "",
    val sniListText: String = "",
    val ipListText: String = "",
    val configEditor: ConfigEditorState = ZeroDpiConfigToml.analyze(""),
    val dirtyFiles: Set<RuntimeFileKind> = emptySet(),
    val isLoading: Boolean = true,
    val isSaving: Boolean = false,
    val statusMessage: String? = null,
    val errorMessage: String? = null,
) {
    val selectedText: String
        get() = textFor(selectedFile)

    val sniListValidation: RuntimeListValidation
        get() = RuntimeListValidator.validate(
            kind = RuntimeFileKind.SniList,
            text = sniListText,
            mode = configEditor.valueFor("MODE"),
        )

    val ipListValidation: RuntimeListValidation
        get() = RuntimeListValidator.validate(
            kind = RuntimeFileKind.IpList,
            text = ipListText,
            mode = configEditor.valueFor("MODE"),
        )

    val selectedListValidation: RuntimeListValidation?
        get() = validationFor(selectedFile)

    val blockingListIssuesForStart: List<RuntimeListIssue>
        get() = when (configEditor.valueFor("MODE")) {
            "sni_scan",
            "sni_spoof",
            "proxy_scan",
            "sni_method_scan",
            -> sniListValidation.issues

            "ip_scan",
            "ip_bypass",
            "ip_bypass_plus",
            "ip_method_scan",
            -> ipListValidation.issues

            else -> emptyList()
        }

    val canStart: Boolean
        get() = configEditor.canStart && blockingListIssuesForStart.isEmpty()

    fun textFor(kind: RuntimeFileKind): String =
        when (kind) {
            RuntimeFileKind.Config -> configText
            RuntimeFileKind.SniList -> sniListText
            RuntimeFileKind.IpList -> ipListText
        }

    fun withText(kind: RuntimeFileKind, text: String): RuntimeFilesUiState =
        when (kind) {
            RuntimeFileKind.Config -> copy(
                configText = text,
                configEditor = ZeroDpiConfigToml.analyze(text),
            )
            RuntimeFileKind.SniList -> copy(sniListText = text)
            RuntimeFileKind.IpList -> copy(ipListText = text)
        }

    fun validationFor(kind: RuntimeFileKind): RuntimeListValidation? =
        when (kind) {
            RuntimeFileKind.Config -> null
            RuntimeFileKind.SniList -> sniListValidation
            RuntimeFileKind.IpList -> ipListValidation
    }
}

data class ProfileUiState(
    val profiles: List<ZeroDpiProfile> = listOf(ZeroDpiProfile.default()),
    val activeProfileId: String = ZeroDpiProfile.DEFAULT_PROFILE_ID,
    val activeProfileName: String = ZeroDpiProfile.DEFAULT_PROFILE_NAME,
    val profileRemoteSettings: ProfileRemoteSettings = ProfileRemoteSettings(),
    val hasUnsavedProfileRemoteSettings: Boolean = false,
    val pendingSwitchProfileId: String? = null,
    val isProfileLoading: Boolean = true,
    val isProfileSwitching: Boolean = false,
    val isRemoteUpdating: Boolean = false,
    val statusMessage: String? = null,
    val lastProfileError: String? = null,
) {
    val activeProfile: ZeroDpiProfile?
        get() = profiles.firstOrNull { it.id == activeProfileId }

    val pendingSwitchProfile: ZeroDpiProfile?
        get() = pendingSwitchProfileId?.let { targetId ->
            profiles.firstOrNull { it.id == targetId }
        }
}

data class DiagnosticsUiState(
    val diagnostics: DeviceDiagnostics = DeviceDiagnostics.Empty,
    val isRefreshing: Boolean = false,
    val statusMessage: String? = null,
    val errorMessage: String? = null,
)

sealed interface MethodScanPhase {
    data object Hidden : MethodScanPhase
    data object Idle : MethodScanPhase
    data object Running : MethodScanPhase
    data object Completed : MethodScanPhase
    data class Failed(val message: String) : MethodScanPhase
}

data class MethodScanUiState(
    val phase: MethodScanPhase = MethodScanPhase.Hidden,
    val mode: String? = null,
    val progress: ScanProgressInfo? = null,
    val report: MethodScanReportModel? = null,
)

sealed interface TargetPickPhase {
    data object Hidden : TargetPickPhase
    data object Idle : TargetPickPhase
    data object Scanning : TargetPickPhase
    data object Choosing : TargetPickPhase
    data class Failed(val message: String) : TargetPickPhase
}

/** One selectable scan-result row (kind-specific fields flattened). */
data class TargetPickEntryModel(
    val sni: String?,
    val ip: String,
    val score: Int,
    val tcpLatencyMs: Long?,
)

data class TargetPickUiState(
    val phase: TargetPickPhase = TargetPickPhase.Hidden,
    val mode: String? = null,
    val pin: TargetPin? = null,
    val progress: ScanProgressInfo? = null,
    val entries: List<TargetPickEntryModel>? = null,
    val resumeAvailable: Boolean = false,
    val origin: PickOrigin? = null,
)

class MainViewModel(
    application: Application,
    private val profileRepository: ProfileRepository = ProfileRepository(application.applicationContext),
    private val runtimeStorage: RuntimeStorage = RuntimeStorage(application.applicationContext),
    private val profileUpdateManager: ProfileUpdater = ProfileUpdateManager(profileRepository),
    private val autoUpdateReconciler: suspend (Context, ProfileIndex) -> Unit = { context, index ->
        ProfileAutoUpdateScheduler.reconcile(context, index)
    },
    private val bindServiceOnInit: Boolean = true,
) : AndroidViewModel(application) {
    constructor(application: Application) : this(
        application = application,
        profileRepository = ProfileRepository(application.applicationContext),
        runtimeStorage = RuntimeStorage(application.applicationContext),
    )

    private val appContext = application.applicationContext
    private val diagnosticsProvider = AndroidDiagnosticsProvider(appContext)
    private val _uiState = MutableStateFlow(ZeroDpiServiceState())
    val uiState: StateFlow<ZeroDpiServiceState> = _uiState.asStateFlow()
    private val _runtimeFilesState = MutableStateFlow(RuntimeFilesUiState())
    val runtimeFilesState: StateFlow<RuntimeFilesUiState> = _runtimeFilesState.asStateFlow()
    private val _profileState = MutableStateFlow(ProfileUiState())
    val profileState: StateFlow<ProfileUiState> = _profileState.asStateFlow()
    private val _diagnosticsState = MutableStateFlow(DiagnosticsUiState())
    val diagnosticsState: StateFlow<DiagnosticsUiState> = _diagnosticsState.asStateFlow()
    private val _methodScanState = MutableStateFlow(MethodScanUiState())
    val methodScanState: StateFlow<MethodScanUiState> = _methodScanState.asStateFlow()
    private val _targetPickState = MutableStateFlow(TargetPickUiState())
    val targetPickState: StateFlow<TargetPickUiState> = _targetPickState.asStateFlow()

    private var pinStore: TargetPinStore? = null
    private var lastPickGeneration = 0
    private var loadedPickGeneration = -1

    private var lastServiceStatus: RuntimeStatus? = null

    private var service: ZeroDpiService? = null
    private var serviceStateJob: Job? = null
    private var isBound = false
    private var startWhenConnected = false
    private var startWhenConnectedProfileId: String? = null
    private var startWhenConnectedModeOverride: String? = null
    private var remoteSettingsSaveJob: Job? = null
    private var runtimeFilesAutoSaveJob: Job? = null
    private val runtimeFilesSaveMutex = Mutex()

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            isBound = true
            service = (binder as ZeroDpiService.LocalBinder).service()
            serviceStateJob?.cancel()
            serviceStateJob = viewModelScope.launch {
                service?.state()?.collect { state ->
                    _uiState.value = state
                    syncIdleRuntimeStateFromConfig()
                    updateMethodScanState(state)
                    updateTargetPickState(state)
                }
            }
            if (startWhenConnected) {
                startWhenConnected = false
                val profileId = startWhenConnectedProfileId ?: ZeroDpiProfile.DEFAULT_PROFILE_ID
                val modeOverride = startWhenConnectedModeOverride
                startWhenConnectedProfileId = null
                startWhenConnectedModeOverride = null
                service?.startZeroDpi(profileId = profileId, modeOverride = modeOverride)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            serviceStateJob?.cancel()
            serviceStateJob = null
            service = null
            isBound = false
            _uiState.value = _uiState.value.copy(status = RuntimeStatus.Stopped)
            syncIdleRuntimeStateFromConfig()
            updateMethodScanState(_uiState.value)
            updateTargetPickState(_uiState.value)
        }
    }

    init {
        if (bindServiceOnInit) {
            bindService()
        }
        loadRuntimeFiles()
    }

    fun start() {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("starting ZeroDPI")) {
                return@launch
            }

            cancelPendingRuntimeFilesAutoSave()

            val validation = ZeroDpiConfigToml.analyze(_runtimeFilesState.value.configText)
            if (!validation.canStart) {
                _runtimeFilesState.update {
                    it.copy(
                        configEditor = validation,
                        statusMessage = null,
                        errorMessage = "Fix config validation errors before starting ZeroDPI.",
                    )
                }
                return@launch
            }

            val blockingListIssues = _runtimeFilesState.value.copy(configEditor = validation)
                .blockingListIssuesForStart
            if (blockingListIssues.isNotEmpty()) {
                _runtimeFilesState.update {
                    it.copy(
                        configEditor = validation,
                        statusMessage = null,
                        errorMessage = "Fix list validation errors before starting ZeroDPI.",
                    )
                }
                return@launch
            }

            val startConfigText = ZeroDpiConfigToml.methodScanStartConfigText(
                _runtimeFilesState.value.configText,
            )
            if (startConfigText != _runtimeFilesState.value.configText) {
                _runtimeFilesState.update { current ->
                    current
                        .withText(RuntimeFileKind.Config, startConfigText)
                        .copy(
                            configEditor = ZeroDpiConfigToml.analyze(startConfigText),
                            dirtyFiles = current.dirtyFiles + RuntimeFileKind.Config,
                        )
                }
            }

            _runtimeFilesState.update {
                it.copy(
                    configEditor = validation,
                    statusMessage = validation.rootRequirement.message,
                    errorMessage = null,
                )
            }

            if (saveRuntimeFiles(RuntimeFileKind.entries.toSet())) {
                startService()
            }
        }
    }

    fun stop() {
        service?.stopZeroDpi()
    }

    fun requestTargetPick() {
        viewModelScope.launch {
            lastPickGeneration += 1
            service?.requestTargetPick(_runtimeFilesState.value.activeProfileId)
        }
    }

    fun cancelTargetPick() {
        service?.cancelTargetPick()
    }

    fun chooseTarget(entry: TargetPickEntryModel) {
        viewModelScope.launch {
            val profileId = _runtimeFilesState.value.activeProfileId
            val configEditor = _runtimeFilesState.value.configEditor
            val kind = TargetPickPolicy.pinKindForMode(configEditor.valueFor("MODE")) ?: return@launch
            val pin = TargetPin(
                kind = kind,
                sni = entry.sni,
                ip = entry.ip,
                score = entry.score.takeIf { it > 0 },
                pickedAtMs = System.currentTimeMillis(),
            )
            runCatching { pinStore().write(profileId, pin) }
                .onSuccess {
                    _targetPickState.update { it.copy(pin = pin) }
                    service?.applyTargetPick()
                }
                .onFailure { error ->
                    _targetPickState.update {
                        it.copy(
                            phase = TargetPickPhase.Failed(
                                error.message ?: "Could not save the target pin.",
                            ),
                        )
                    }
                }
        }
    }

    fun clearTargetPin() {
        viewModelScope.launch {
            val profileId = _runtimeFilesState.value.activeProfileId
            runCatching { pinStore().clear(profileId) }
                .onSuccess {
                    _targetPickState.update { it.copy(pin = null) }
                    _runtimeFilesState.update {
                        it.copy(
                            statusMessage = "Cleared the pinned target; the next start will scan and ask again.",
                        )
                    }
                }
                .onFailure { error ->
                    _runtimeFilesState.update {
                        it.copy(errorMessage = error.message ?: "Could not clear the target pin.")
                    }
                }
        }
    }

    fun refreshTargetPin() {
        viewModelScope.launch {
            val profileId = _runtimeFilesState.value.activeProfileId
            val pin = runCatching { pinStore().read(profileId) }.getOrNull()
            _targetPickState.update { it.copy(pin = pin) }
        }
    }

    private fun pinStore(): TargetPinStore {
        val existing = pinStore
        if (existing != null) {
            return existing
        }
        return TargetPinStore(appContext).also { pinStore = it }
    }

    fun forceStop() {
        service?.forceStopZeroDpi()
    }

    fun clearLogs() {
        service?.clearLogs()
    }

    fun runRootDiagnostics() {
        val validation = ZeroDpiConfigToml.analyze(_runtimeFilesState.value.configText)
        _runtimeFilesState.update {
            it.copy(
                configEditor = validation,
                statusMessage = "Root diagnostics will invoke su. ${validation.rootRequirement.message}",
                errorMessage = null,
            )
        }

        val connectedService = service
        if (connectedService == null) {
            bindService()
            _runtimeFilesState.update {
                it.copy(
                    statusMessage = null,
                    errorMessage = "Service is still connecting; try root diagnostics again.",
                )
            }
            return
        }

        connectedService.runRootDiagnostics(
            rootExplanation = validation.rootRequirement.message,
            rootlessAlternatives = validation.rootRequirement.alternatives,
            firewallBackend = validation.valueFor("LINUX_FIREWALL_BACKEND").ifBlank { "iptables" },
        )
    }

    fun refreshDiagnostics() {
        viewModelScope.launch {
            refreshDiagnosticsSnapshot()
        }
    }

    fun refreshProfilesFromDiskOnForeground() {
        viewModelScope.launch {
            val profileSnapshot = _profileState.value
            val runtimeSnapshot = _runtimeFilesState.value
            if (
                profileSnapshot.isProfileLoading ||
                profileSnapshot.isRemoteUpdating ||
                runtimeSnapshot.isLoading
            ) {
                return@launch
            }

            val index = runCatching {
                profileRepository.loadIndex()
            }.getOrElse { error ->
                reportProfileError(error, "Failed to refresh profile status.")
                return@launch
            }
            reconcileAutoUpdateWork(index)

            if (runtimeSnapshot.dirtyFiles.isEmpty() && !profileSnapshot.hasUnsavedProfileRemoteSettings) {
                loadActiveRuntimeFiles(
                    profileIndex = index,
                    statusMessage = "Runtime files refreshed.",
                )
            } else if (!profileSnapshot.hasUnsavedProfileRemoteSettings) {
                applyProfileIndex(index, statusMessage = "Profile status refreshed.")
            }
        }
    }

    suspend fun exportSupportBundle(
        output: OutputStream,
        includePrivateLists: Boolean,
    ) {
        val diagnostics = diagnosticsProvider.collect(
            serviceState = _uiState.value,
            configText = _runtimeFilesState.value.configText,
        )
        runtimeStorage.exportSupportBundle(
            profileId = _runtimeFilesState.value.activeProfileId,
            output = output,
            diagnostics = diagnostics,
            includePrivateLists = includePrivateLists,
        )
        _diagnosticsState.update {
            it.copy(
                diagnostics = diagnostics,
                isRefreshing = false,
                statusMessage = "Support bundle exported.",
                errorMessage = null,
            )
        }
    }

    fun reportSupportBundleExportResult(
        successMessage: String?,
        errorMessage: String?,
    ) {
        _diagnosticsState.update { current ->
            if (errorMessage == null) {
                current.copy(statusMessage = successMessage, errorMessage = null)
            } else {
                current.copy(statusMessage = null, errorMessage = errorMessage)
            }
        }
    }

    fun selectRuntimeFile(kind: RuntimeFileKind) {
        _runtimeFilesState.update { it.copy(selectedFile = kind) }
    }

    fun updateRuntimeFileText(kind: RuntimeFileKind, text: String) {
        _runtimeFilesState.update { current ->
            current
                .withText(kind, text)
                .copy(
                    dirtyFiles = current.dirtyFiles + kind,
                    statusMessage = "Saving changes automatically.",
                    errorMessage = null,
                )
        }
        if (kind == RuntimeFileKind.Config) {
            syncIdleRuntimeStateFromConfig()
        }
        scheduleRuntimeFilesAutoSave()
    }

    fun updateConfigField(fieldName: String, value: String) {
        _runtimeFilesState.update { current ->
            val updatedConfig = ZeroDpiConfigToml.replaceOrAppendField(
                text = current.configText,
                fieldName = fieldName,
                value = value,
            )
            current
                .withText(RuntimeFileKind.Config, updatedConfig)
                .copy(
                    dirtyFiles = current.dirtyFiles + RuntimeFileKind.Config,
                    statusMessage = "Saving config changes automatically.",
                    errorMessage = null,
                )
        }
        syncIdleRuntimeStateFromConfig()
        scheduleRuntimeFilesAutoSave()
    }

    fun saveSelectedRuntimeFile() {
        saveRuntimeFile(_runtimeFilesState.value.selectedFile)
    }

    fun saveRuntimeFile(kind: RuntimeFileKind) {
        cancelPendingRuntimeFilesAutoSave()
        viewModelScope.launch {
            saveRuntimeFiles(setOf(kind))
        }
    }

    fun importRuntimeFileText(kind: RuntimeFileKind, text: String) {
        _runtimeFilesState.update { current ->
            current
                .withText(kind, text)
                .copy(
                    selectedFile = kind,
                    dirtyFiles = current.dirtyFiles + kind,
                    statusMessage = "Imported ${kind.fileName}. Saving changes automatically.",
                    errorMessage = null,
                )
        }
        if (kind == RuntimeFileKind.Config) {
            syncIdleRuntimeStateFromConfig()
        }
        scheduleRuntimeFilesAutoSave()
    }

    fun reportRuntimeFileTransferResult(
        successMessage: String?,
        errorMessage: String?,
    ) {
        _runtimeFilesState.update { current ->
            if (errorMessage == null) {
                current.copy(
                    statusMessage = successMessage,
                    errorMessage = null,
                )
            } else {
                current.copy(
                    statusMessage = null,
                    errorMessage = errorMessage,
                )
            }
        }
    }

    fun runTestScan(kind: RuntimeFileKind) {
        val mode = when (kind) {
            RuntimeFileKind.SniList -> "sni_scan"
            RuntimeFileKind.IpList -> "ip_scan"
            RuntimeFileKind.Config -> return
        }

        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("running test scans")) {
                return@launch
            }

            val snapshot = _runtimeFilesState.value
            val scanConfigText = ZeroDpiConfigToml.replaceOrAppendField(
                text = snapshot.configText,
                fieldName = "MODE",
                value = mode,
            )
            val validation = ZeroDpiConfigToml.analyze(scanConfigText)
            if (!validation.canStart) {
                _runtimeFilesState.update {
                    it.copy(
                        statusMessage = null,
                        errorMessage = "Fix config validation errors before running $mode.",
                    )
                }
                return@launch
            }

            val listValidation = RuntimeListValidator.validate(
                kind = kind,
                text = snapshot.textFor(kind),
                mode = mode,
            )
            if (!listValidation.isValid) {
                _runtimeFilesState.update {
                    it.copy(
                        selectedFile = kind,
                        statusMessage = null,
                        errorMessage = "Fix ${kind.fileName} validation errors before running $mode.",
                    )
                }
                return@launch
            }

            _runtimeFilesState.update {
                it.copy(
                    statusMessage = "Starting rootless $mode test scan.",
                    errorMessage = null,
                )
            }

            if (flushPendingRuntimeFilesAutoSave()) {
                startService(mode)
            }
        }
    }

    fun resetSelectedRuntimeFileToDefaults() {
        resetRuntimeFileToDefaults(_runtimeFilesState.value.selectedFile)
    }

    fun resetRuntimeFileToDefaults(kind: RuntimeFileKind) {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("resetting profile files")) {
                return@launch
            }
            cancelPendingRuntimeFilesAutoSave()

            _runtimeFilesState.update {
                it.copy(isSaving = true, statusMessage = null, errorMessage = null)
            }
            runCatching {
                runtimeStorage.resetToDefaults(
                    profileId = _runtimeFilesState.value.activeProfileId,
                    kind = kind,
                )
            }.onSuccess { defaultText ->
                _runtimeFilesState.update { current ->
                    current
                        .withText(kind, defaultText)
                        .copy(
                            dirtyFiles = current.dirtyFiles - kind,
                            isSaving = false,
                            statusMessage = "Reset ${kind.fileName} to defaults.",
                            errorMessage = null,
                        )
                }
                if (kind == RuntimeFileKind.Config) {
                    syncIdleRuntimeStateFromConfig()
                }
            }.onFailure { error ->
                _runtimeFilesState.update {
                    it.copy(
                        isSaving = false,
                        errorMessage = error.message ?: "Failed to reset ${kind.fileName}.",
                    )
                }
            }
        }
    }

    fun createProfileFromDefaults(name: String) {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("creating profiles")) {
                return@launch
            }
            if (!ensureRuntimeInactive("creating profiles")) {
                return@launch
            }
            setProfileLoading()
            runCatching {
                profileRepository.createProfile(name.trim())
            }.onSuccess { index ->
                applyProfileIndex(index, statusMessage = "Created profile \"${name.trim()}\".")
            }.onFailure { error ->
                reportProfileError(error, "Failed to create profile.")
            }
        }
    }

    fun duplicateActiveProfile(name: String) {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("duplicating profiles")) {
                return@launch
            }
            if (!ensureRuntimeInactive("duplicating profiles")) {
                return@launch
            }
            if (!flushPendingRuntimeFilesAutoSave()) {
                return@launch
            }
            setProfileLoading()
            val sourceProfileId = _runtimeFilesState.value.activeProfileId
            runCatching {
                profileRepository.duplicateProfile(
                    sourceProfileId = sourceProfileId,
                    name = name.trim(),
                )
            }.onSuccess { index ->
                applyProfileIndex(index, statusMessage = "Duplicated active profile.")
            }.onFailure { error ->
                reportProfileError(error, "Failed to duplicate active profile.")
            }
        }
    }

    fun renameProfile(profileId: String, name: String) {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("renaming profiles")) {
                return@launch
            }
            if (!ensureRuntimeInactive("renaming profiles")) {
                return@launch
            }
            setProfileLoading()
            runCatching {
                profileRepository.renameProfile(profileId = profileId, name = name.trim())
            }.onSuccess { index ->
                applyProfileIndex(index, statusMessage = "Renamed profile.")
            }.onFailure { error ->
                reportProfileError(error, "Failed to rename profile.")
            }
        }
    }

    fun deleteProfile(profileId: String) {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("deleting profiles")) {
                return@launch
            }
            if (!ensureRuntimeInactive("deleting profiles")) {
                return@launch
            }
            val snapshot = _runtimeFilesState.value
            if (profileId == snapshot.activeProfileId && !flushPendingRuntimeFilesAutoSave()) {
                return@launch
            }

            setProfileLoading()
            runCatching {
                profileRepository.deleteProfile(profileId)
            }.onSuccess { index ->
                if (index.activeProfileId == snapshot.activeProfileId) {
                    applyProfileIndex(index, statusMessage = "Deleted profile.")
                } else {
                    loadActiveRuntimeFiles(
                        profileIndex = index,
                        isSwitching = true,
                        statusMessage = "Deleted profile and switched active profile.",
                    )
                }
            }.onFailure { error ->
                reportProfileError(error, "Failed to delete profile.")
            }
        }
    }

    fun selectProfile(profileId: String) {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("switching profiles")) {
                return@launch
            }
            if (profileId == _runtimeFilesState.value.activeProfileId) {
                _profileState.update {
                    it.copy(
                        pendingSwitchProfileId = null,
                        statusMessage = "Profile already selected.",
                        lastProfileError = null,
                    )
                }
                return@launch
            }
            if (!ensureRuntimeInactive("switching profiles")) {
                return@launch
            }
            val hadPendingChanges = _runtimeFilesState.value.dirtyFiles.isNotEmpty()
            if (!flushPendingRuntimeFilesAutoSave()) {
                return@launch
            }

            switchToProfile(
                profileId,
                statusMessage = if (hadPendingChanges) {
                    "Saved changes and switched profile."
                } else {
                    "Switched profile."
                },
            )
        }
    }

    fun saveAndSelectProfile(profileId: String? = null) {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("switching profiles")) {
                return@launch
            }

            val targetProfileId = profileId ?: _profileState.value.pendingSwitchProfileId
            if (targetProfileId == null) {
                setProfileError("No pending profile switch.")
                return@launch
            }
            if (!ensureRuntimeInactive("switching profiles")) {
                return@launch
            }

            if (!flushPendingRuntimeFilesAutoSave()) {
                return@launch
            }
            switchToProfile(targetProfileId, statusMessage = "Saved edits and switched profile.")
        }
    }

    fun discardAndSelectProfile(profileId: String? = null) {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("switching profiles")) {
                return@launch
            }

            val targetProfileId = profileId ?: _profileState.value.pendingSwitchProfileId
            if (targetProfileId == null) {
                setProfileError("No pending profile switch.")
                return@launch
            }
            if (!ensureRuntimeInactive("switching profiles")) {
                return@launch
            }

            switchToProfile(targetProfileId, statusMessage = "Discarded edits and switched profile.")
        }
    }

    fun cancelProfileSwitch() {
        _profileState.update {
            it.copy(
                pendingSwitchProfileId = null,
                isProfileSwitching = false,
                statusMessage = "Profile switch canceled.",
                lastProfileError = null,
            )
        }
    }

    fun updateActiveProfileRemoteConfigUrl(configUrl: String) {
        updateActiveProfileRemoteSettings(
            _profileState.value.profileRemoteSettings.copy(configUrl = configUrl),
        )
    }

    fun updateActiveProfileRemoteSniListUrl(sniListUrl: String) {
        updateActiveProfileRemoteSettings(
            _profileState.value.profileRemoteSettings.copy(sniListUrl = sniListUrl),
        )
    }

    fun updateActiveProfileRemoteIpListUrl(ipListUrl: String) {
        updateActiveProfileRemoteSettings(
            _profileState.value.profileRemoteSettings.copy(ipListUrl = ipListUrl),
        )
    }

    fun toggleActiveProfileAutoUpdate(enabled: Boolean) {
        updateActiveProfileRemoteSettings(
            _profileState.value.profileRemoteSettings.copy(autoUpdateEnabled = enabled),
        )
    }

    fun updateActiveProfileAutoUpdateIntervalHours(intervalHours: Int) {
        updateActiveProfileRemoteSettings(
            _profileState.value.profileRemoteSettings.copy(autoUpdateIntervalHours = intervalHours),
        )
    }

    fun updateActiveProfileRemoteSettings(remote: ProfileRemoteSettings) {
        if (!ensureRemoteUpdateInactive("changing remote settings")) {
            return
        }

        val activeProfileId = _profileState.value.activeProfileId
        val validation = remote.validate()
        remoteSettingsSaveJob?.cancel()
        _profileState.update {
            it.copy(
                profileRemoteSettings = remote,
                hasUnsavedProfileRemoteSettings = true,
                statusMessage = if (validation.isValid) {
                    "Saving profile remote settings."
                } else {
                    null
                },
                lastProfileError = if (validation.isValid) null else validation.validationMessage(),
            )
        }
        if (!validation.isValid) {
            return
        }

        remoteSettingsSaveJob = viewModelScope.launch {
            runCatching {
                profileRepository.updateRemoteSettings(
                    profileId = activeProfileId,
                    remote = remote,
                )
            }.onSuccess { index ->
                if (_runtimeFilesState.value.activeProfileId == activeProfileId) {
                    applyProfileIndex(index, statusMessage = "Saved profile remote settings.")
                } else {
                    _profileState.update {
                        it.copy(
                            isProfileLoading = false,
                            statusMessage = "Saved profile remote settings.",
                            lastProfileError = null,
                        )
                    }
                }
            }.onFailure { error ->
                reportProfileError(error, "Failed to save profile remote settings.")
            }
        }
    }

    fun runManualRemoteUpdate() {
        updateActiveProfileFromRemote()
    }

    fun updateActiveProfileFromRemote() {
        viewModelScope.launch {
            if (!ensureRemoteUpdateInactive("starting another remote update")) {
                return@launch
            }
            if (!ensureRuntimeInactive("updating profiles from remote")) {
                return@launch
            }

            val profileId = _profileState.value.activeProfileId
            val remoteSettings = _profileState.value.profileRemoteSettings
            val remoteValidation = remoteSettings.validateForUpdate()
            if (!remoteValidation.isValid) {
                setProfileError(
                    remoteValidation.validationMessage(
                        fallbackMessage = "Configure all three valid remote URLs before updating.",
                    ),
                )
                return@launch
            }

            if (!flushPendingRuntimeFilesAutoSave()) {
                return@launch
            }

            remoteSettingsSaveJob?.cancel()
            remoteSettingsSaveJob = null
            _profileState.update {
                it.copy(isRemoteUpdating = true, statusMessage = null, lastProfileError = null)
            }
            runCatching {
                profileUpdateManager.updateProfile(
                    profileId = profileId,
                    mode = ProfileUpdateMode.Manual,
                    remote = remoteSettings,
                )
            }.onSuccess { result ->
                if (result.successful) {
                    loadActiveRuntimeFiles(
                        profileIndex = result.index,
                        statusMessage = result.message,
                    )
                } else {
                    applyRemoteUpdateFailure(result)
                }
            }.onFailure { error ->
                reportProfileError(error, "Failed to update profile from remote.")
            }
        }
    }

    private fun startService(modeOverride: String? = null) {
        val profileId = _runtimeFilesState.value.activeProfileId
        val intent = Intent(appContext, ZeroDpiService::class.java)
        startWhenConnected = true
        startWhenConnectedProfileId = profileId
        startWhenConnectedModeOverride = modeOverride
        ZeroDpiRuntimeStateStore.markRuntimeActive(appContext, profileId = profileId)
        ContextCompat.startForegroundService(appContext, intent)
        bindService()
        service?.let {
            startWhenConnected = false
            startWhenConnectedProfileId = null
            startWhenConnectedModeOverride = null
            it.startZeroDpi(profileId = profileId, modeOverride = modeOverride)
        }
    }

    private fun bindService() {
        if (isBound) {
            return
        }
        val intent = Intent(appContext, ZeroDpiService::class.java)
        isBound = appContext.bindService(intent, connection, Context.BIND_AUTO_CREATE)
    }

    private fun loadRuntimeFiles() {
        viewModelScope.launch {
            loadActiveRuntimeFiles(statusMessage = "Runtime files loaded.")
        }
    }

    private suspend fun loadActiveRuntimeFiles(
        profileIndex: ProfileIndex? = null,
        isSwitching: Boolean = false,
        statusMessage: String,
    ): Boolean {
        val selectedFile = _runtimeFilesState.value.selectedFile
        _runtimeFilesState.update {
            it.copy(isLoading = true, errorMessage = null)
        }
        _profileState.update {
            it.copy(
                isProfileLoading = true,
                isProfileSwitching = isSwitching,
                statusMessage = null,
                lastProfileError = null,
            )
        }

        return runCatching {
            val index = profileIndex ?: profileRepository.loadIndex()
            val activeProfile = activeProfileFrom(index)
            val contents = runtimeStorage.readAll(activeProfile.id)
            Triple(index, activeProfile, contents)
        }.fold(
            onSuccess = { (index, activeProfile, contents) ->
                val configEditor = ZeroDpiConfigToml.analyze(contents.configText)
                _profileState.value = ProfileUiState(
                    profiles = index.profiles,
                    activeProfileId = activeProfile.id,
                    activeProfileName = activeProfile.name,
                    profileRemoteSettings = activeProfile.remote,
                    isProfileLoading = false,
                    isProfileSwitching = false,
                    statusMessage = statusMessage,
                    lastProfileError = null,
                )
                _runtimeFilesState.value = RuntimeFilesUiState(
                    selectedFile = selectedFile,
                    activeProfileId = activeProfile.id,
                    activeProfileName = activeProfile.name,
                    runtimeDir = contents.files.runtimeDir.absolutePath,
                    configText = contents.configText,
                    sniListText = contents.sniListText,
                    ipListText = contents.ipListText,
                    configEditor = configEditor,
                    isLoading = false,
                    statusMessage = statusMessage,
                )
                syncIdleRuntimeStateFromConfig(configEditor)
                refreshTargetPin()
                refreshDiagnostics()
                reconcileAutoUpdateWork(index)
                true
            },
            onFailure = { error ->
                val message = error.message ?: "Failed to load runtime files."
                _profileState.update {
                    it.copy(
                        isProfileLoading = false,
                        isProfileSwitching = false,
                        lastProfileError = message,
                    )
                }
                _runtimeFilesState.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = message,
                    )
                }
                refreshDiagnostics()
                false
            },
        )
    }

    private suspend fun switchToProfile(
        profileId: String,
        statusMessage: String,
    ): Boolean {
        cancelPendingRuntimeFilesAutoSave()
        remoteSettingsSaveJob?.cancel()
        remoteSettingsSaveJob = null
        _profileState.update {
            it.copy(
                isProfileLoading = true,
                isProfileSwitching = true,
                statusMessage = null,
                lastProfileError = null,
            )
        }
        return runCatching {
            profileRepository.selectProfile(profileId)
        }.fold(
            onSuccess = { index ->
                loadActiveRuntimeFiles(
                    profileIndex = index,
                    isSwitching = true,
                    statusMessage = statusMessage,
                )
            },
            onFailure = { error ->
                reportProfileError(error, "Failed to switch profile.")
                false
            },
        )
    }

    private fun applyProfileIndex(
        index: ProfileIndex,
        statusMessage: String,
    ) {
        val activeProfile = activeProfileFrom(index)
        _profileState.value = _profileState.value.copy(
            profiles = index.profiles,
            activeProfileId = activeProfile.id,
            activeProfileName = activeProfile.name,
            profileRemoteSettings = activeProfile.remote,
            hasUnsavedProfileRemoteSettings = false,
            pendingSwitchProfileId = null,
            isProfileLoading = false,
            isProfileSwitching = false,
            isRemoteUpdating = false,
            statusMessage = statusMessage,
            lastProfileError = null,
        )
        _runtimeFilesState.update {
            it.copy(
                activeProfileId = activeProfile.id,
                activeProfileName = activeProfile.name,
                statusMessage = statusMessage,
                errorMessage = null,
            )
        }
        reconcileAutoUpdateWork(index)
    }

    private fun applyRemoteUpdateFailure(result: ProfileUpdateResult) {
        val activeProfile = activeProfileFrom(result.index)
        val currentRemote = _profileState.value.profileRemoteSettings
        val keepUnsavedRemote = !currentRemote.validate().isValid
        _profileState.value = _profileState.value.copy(
            profiles = result.index.profiles,
            activeProfileId = activeProfile.id,
            activeProfileName = activeProfile.name,
            profileRemoteSettings = if (keepUnsavedRemote) currentRemote else activeProfile.remote,
            hasUnsavedProfileRemoteSettings = keepUnsavedRemote,
            isProfileLoading = false,
            isProfileSwitching = false,
            isRemoteUpdating = false,
            statusMessage = null,
            lastProfileError = result.message,
        )
        _runtimeFilesState.update {
            it.copy(statusMessage = null, errorMessage = result.message)
        }
        reconcileAutoUpdateWork(result.index)
    }

    private fun reconcileAutoUpdateWork(index: ProfileIndex) {
        viewModelScope.launch {
            runCatching {
                autoUpdateReconciler(appContext, index)
            }.onFailure { error ->
                _profileState.update {
                    it.copy(
                        statusMessage = null,
                        lastProfileError = error.message ?: "Failed to schedule automatic updates.",
                    )
                }
            }
        }
    }

    private fun activeProfileFrom(index: ProfileIndex): ZeroDpiProfile =
        index.profiles.first { it.id == index.activeProfileId }

    private fun setProfileLoading() {
        _profileState.update {
            it.copy(
                isProfileLoading = true,
                statusMessage = null,
                lastProfileError = null,
            )
        }
    }

    private fun ensureRuntimeInactive(action: String): Boolean {
        if (!isRuntimeActive()) {
            return true
        }
        setProfileError("Stop ZeroDPI before $action.")
        return false
    }

    private fun ensureRemoteUpdateInactive(action: String): Boolean {
        if (!_profileState.value.isRemoteUpdating) {
            return true
        }
        val message = "Wait for the remote update to finish before $action."
        _profileState.update {
            it.copy(statusMessage = null, lastProfileError = message)
        }
        _runtimeFilesState.update {
            it.copy(statusMessage = null, errorMessage = message)
        }
        return false
    }

    private fun isRuntimeActive(): Boolean =
        when (_uiState.value.status) {
            RuntimeStatus.Starting,
            RuntimeStatus.Scanning,
            RuntimeStatus.Running,
            RuntimeStatus.Restarting,
            RuntimeStatus.Choosing,
            RuntimeStatus.Stopping,
            -> true

            RuntimeStatus.Stopped,
            RuntimeStatus.Failed,
            -> false
        }

    private fun syncIdleRuntimeStateFromConfig(
        configEditor: ConfigEditorState = _runtimeFilesState.value.configEditor,
    ) {
        _uiState.update { current ->
            if (current.status != RuntimeStatus.Stopped) {
                return@update current
            }

            val mode = configEditor.valueFor("MODE").ifBlank { current.mode }
            val bypassMethod = ZeroDpiConfigToml.displayMethodList(
                configEditor.valueFor("BYPASS_METHOD"),
            ).ifBlank { current.bypassMethod }
            val listenHost = configEditor.valueFor("LISTEN_HOST").ifBlank { "127.0.0.1" }
            val listenPort = configEditor.valueFor("LISTEN_PORT").ifBlank { "44444" }

            current.copy(
                rootStatus = if (configEditor.rootRequirement.requiresRoot) {
                    RootStatus.Needed
                } else {
                    RootStatus.NotNeeded
                },
                mode = mode,
                bypassMethod = bypassMethod,
                listener = "$listenHost:$listenPort",
            )
        }
        updateMethodScanState(_uiState.value)
        updateTargetPickState(_uiState.value)
    }

    private fun updateMethodScanState(serviceState: ZeroDpiServiceState) {
        val mode = _runtimeFilesState.value.configEditor.valueFor("MODE")
        val visible = mode in ZeroDpiConfigSchema.methodScanModes
        if (!visible) {
            lastServiceStatus = serviceState.status
            _methodScanState.value = MethodScanUiState()
            return
        }

        val previous = lastServiceStatus
        lastServiceStatus = serviceState.status
        val transient = serviceState.status in setOf(
            RuntimeStatus.Starting, RuntimeStatus.Scanning, RuntimeStatus.Restarting,
        )
        if (transient) {
            _methodScanState.value = MethodScanUiState(
                phase = MethodScanPhase.Running,
                mode = mode,
                progress = serviceState.scanProgress,
            )
            return
        }

        if (previous != null && previous in setOf(
                RuntimeStatus.Starting, RuntimeStatus.Scanning, RuntimeStatus.Restarting,
            )
        ) {
            val profileId = _runtimeFilesState.value.activeProfileId
            val configText = _runtimeFilesState.value.configText
            viewModelScope.launch {
                val raw = runCatching { runtimeStorage.readMethodScanOutput(profileId, configText) }.getOrNull()
                val report = raw?.let { MethodScanReportParser.parse(it) }
                _methodScanState.value = MethodScanUiState(
                    phase = if (report != null) {
                        MethodScanPhase.Completed
                    } else {
                        MethodScanPhase.Failed(
                            serviceState.lastError
                                ?.let { "Method scan failed: $it" }
                                ?: "Method scan finished without a report.",
                        )
                    },
                    mode = mode,
                    report = report,
                )
            }
            return
        }

        _methodScanState.value = MethodScanUiState(phase = MethodScanPhase.Idle, mode = mode)
    }

    private fun updateTargetPickState(serviceState: ZeroDpiServiceState) {
        val editor = _runtimeFilesState.value.configEditor
        val mode = editor.valueFor("MODE")
        val visible = TargetPickPolicy.scanModeFor(mode) != null &&
            editor.valueFor("AUTO_SELECT") == "false"
        if (!visible) {
            _targetPickState.value = TargetPickUiState()
            return
        }
        val session = serviceState.pickSession
        val current = _targetPickState.value
        when {
            session?.phase == PickPhase.Choosing -> {
                if (loadedPickGeneration != lastPickGeneration) {
                    loadedPickGeneration = lastPickGeneration
                    loadPickResults(mode)
                } else {
                    _targetPickState.value = current.copy(
                        phase = TargetPickPhase.Choosing,
                        mode = mode,
                        resumeAvailable = session.resumeAvailable,
                        origin = session.origin,
                    )
                }
            }
            session?.phase == PickPhase.Scanning -> {
                _targetPickState.value = current.copy(
                    phase = TargetPickPhase.Scanning,
                    mode = mode,
                    progress = serviceState.scanProgress,
                    resumeAvailable = session.resumeAvailable,
                    origin = session.origin,
                )
            }
            else -> {
                if (current.phase != TargetPickPhase.Idle) {
                    refreshTargetPin()
                }
                _targetPickState.value = current.copy(
                    phase = TargetPickPhase.Idle,
                    mode = mode,
                    progress = null,
                    entries = null,
                    resumeAvailable = session?.resumeAvailable ?: false,
                    origin = session?.origin,
                )
            }
        }
    }

    private fun loadPickResults(mode: String) {
        viewModelScope.launch {
            val profileId = _runtimeFilesState.value.activeProfileId
            val current = _targetPickState.value
            val raw = runCatching { runtimeStorage.readPickScanResults(profileId) }.getOrNull()
            val entries = raw?.let { text ->
                when (TargetPickPolicy.scanModeFor(mode)) {
                    "sni_scan" -> ScanResultParser.parseSni(text)?.map { entry ->
                        TargetPickEntryModel(entry.sni, entry.ip, entry.score, entry.tcpLatencyMs)
                    }
                    "ip_scan" -> ScanResultParser.parseIp(text)?.map { entry ->
                        TargetPickEntryModel(null, entry.ip, entry.score, entry.tcpLatencyMs)
                    }
                    else -> null
                }
            }
            _targetPickState.value = if (entries != null) {
                current.copy(
                    phase = TargetPickPhase.Choosing,
                    mode = mode,
                    entries = entries,
                )
            } else {
                current.copy(
                    phase = TargetPickPhase.Failed(
                        raw?.let { "Scan results could not be parsed." }
                            ?: "The scan finished without results. Check the SNI/IP list and try again.",
                    ),
                    mode = mode,
                    entries = null,
                )
            }
        }
    }

    private fun reportProfileError(error: Throwable, fallbackMessage: String) {
        setProfileError(error.message ?: fallbackMessage)
    }

    private fun setProfileError(message: String) {
        _profileState.update {
            it.copy(
                isProfileLoading = false,
                isProfileSwitching = false,
                isRemoteUpdating = false,
                statusMessage = null,
                lastProfileError = message,
            )
        }
        _runtimeFilesState.update {
            it.copy(statusMessage = null, errorMessage = message)
        }
    }

    private fun ProfileValidationResult.validationMessage(
        fallbackMessage: String = "Profile validation failed.",
    ): String =
        errors.joinToString("; ") { it.message }.ifBlank { fallbackMessage }

    private suspend fun refreshDiagnosticsSnapshot() {
        _diagnosticsState.update {
            it.copy(isRefreshing = true, statusMessage = null, errorMessage = null)
        }
        runCatching {
            diagnosticsProvider.collect(
                serviceState = _uiState.value,
                configText = _runtimeFilesState.value.configText,
            )
        }.onSuccess { diagnostics ->
            _diagnosticsState.update {
                it.copy(
                    diagnostics = diagnostics,
                    isRefreshing = false,
                    statusMessage = "Diagnostics refreshed.",
                    errorMessage = null,
                )
            }
        }.onFailure { error ->
            _diagnosticsState.update {
                it.copy(
                    isRefreshing = false,
                    errorMessage = error.message ?: "Failed to refresh diagnostics.",
                )
            }
        }
    }

    private fun scheduleRuntimeFilesAutoSave() {
        runtimeFilesAutoSaveJob?.cancel()
        runtimeFilesAutoSaveJob = viewModelScope.launch {
            delay(RUNTIME_FILES_AUTO_SAVE_DELAY_MS)
            runtimeFilesAutoSaveJob = null
            saveRuntimeFiles(_runtimeFilesState.value.dirtyFiles)
        }
    }

    private fun cancelPendingRuntimeFilesAutoSave() {
        runtimeFilesAutoSaveJob?.cancel()
        runtimeFilesAutoSaveJob = null
    }

    private suspend fun flushPendingRuntimeFilesAutoSave(): Boolean {
        cancelPendingRuntimeFilesAutoSave()
        while (_runtimeFilesState.value.dirtyFiles.isNotEmpty()) {
            if (!saveRuntimeFiles(_runtimeFilesState.value.dirtyFiles)) {
                return false
            }
        }
        return true
    }

    private suspend fun saveRuntimeFiles(filesToSave: Set<RuntimeFileKind>): Boolean =
        runtimeFilesSaveMutex.withLock {
            if (filesToSave.isEmpty()) {
                return@withLock true
            }
            if (!ensureRemoteUpdateInactive("saving profile files")) {
                return@withLock false
            }

            val snapshot = _runtimeFilesState.value
            _runtimeFilesState.update {
                it.copy(
                    isSaving = true,
                    statusMessage = "Saving changes automatically.",
                    errorMessage = null,
                )
            }

            runCatching {
                filesToSave.forEach { kind ->
                    runtimeStorage.save(
                        profileId = snapshot.activeProfileId,
                        kind = kind,
                        content = snapshot.textFor(kind),
                    )
                }
            }.fold(
                onSuccess = {
                    if (RuntimeFileKind.Config in filesToSave) {
                        val savedEditor = ZeroDpiConfigToml.analyze(snapshot.textFor(RuntimeFileKind.Config))
                        if (savedEditor.valueFor("SELECTED_SNI").isNotBlank() ||
                            savedEditor.valueFor("SELECTED_IP").isNotBlank()
                        ) {
                            // One selection mechanism at a time: a manual
                            // SELECTED_* in the config replaces the app pin.
                            runCatching { pinStore().clear(snapshot.activeProfileId) }
                            _targetPickState.update { it.copy(pin = null) }
                        }
                    }
                    _runtimeFilesState.update { current ->
                        val unchangedFiles = filesToSave.filterTo(mutableSetOf()) { kind ->
                            current.activeProfileId == snapshot.activeProfileId &&
                                current.textFor(kind) == snapshot.textFor(kind)
                        }
                        current.copy(
                            dirtyFiles = current.dirtyFiles - unchangedFiles,
                            isSaving = false,
                            statusMessage = if (unchangedFiles == filesToSave) {
                                "Saved ${filesToSave.joinToString { it.fileName }} automatically."
                            } else {
                                "Saving latest changes automatically."
                            },
                        )
                    }
                    true
                },
                onFailure = { error ->
                    _runtimeFilesState.update {
                        it.copy(
                            isSaving = false,
                            statusMessage = null,
                            errorMessage = error.message ?: "Failed to save runtime files automatically.",
                        )
                    }
                    false
                },
            )
        }

    override fun onCleared() {
        serviceStateJob?.cancel()
        remoteSettingsSaveJob?.cancel()
        runtimeFilesAutoSaveJob?.cancel()
        if (isBound) {
            runCatching {
                appContext.unbindService(connection)
            }
        }
        super.onCleared()
    }

    private companion object {
        const val RUNTIME_FILES_AUTO_SAVE_DELAY_MS = 600L
    }
}
