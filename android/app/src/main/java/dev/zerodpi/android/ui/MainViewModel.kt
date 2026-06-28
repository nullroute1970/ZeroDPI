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
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.diagnostics.AndroidDiagnosticsProvider
import dev.zerodpi.android.diagnostics.DeviceDiagnostics
import dev.zerodpi.android.list.RuntimeListIssue
import dev.zerodpi.android.list.RuntimeListValidation
import dev.zerodpi.android.list.RuntimeListValidator
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiService
import dev.zerodpi.android.service.ZeroDpiServiceState
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.storage.RuntimeStorage
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.OutputStream

data class RuntimeFilesUiState(
    val selectedFile: RuntimeFileKind = RuntimeFileKind.Config,
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
            -> sniListValidation.issues

            "ip_scan",
            "ip_bypass",
            "ip_bypass_plus",
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

data class DiagnosticsUiState(
    val diagnostics: DeviceDiagnostics = DeviceDiagnostics.Empty,
    val isRefreshing: Boolean = false,
    val statusMessage: String? = null,
    val errorMessage: String? = null,
)

class MainViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val runtimeStorage = RuntimeStorage(appContext)
    private val diagnosticsProvider = AndroidDiagnosticsProvider(appContext)
    private val _uiState = MutableStateFlow(ZeroDpiServiceState())
    val uiState: StateFlow<ZeroDpiServiceState> = _uiState.asStateFlow()
    private val _runtimeFilesState = MutableStateFlow(RuntimeFilesUiState())
    val runtimeFilesState: StateFlow<RuntimeFilesUiState> = _runtimeFilesState.asStateFlow()
    private val _diagnosticsState = MutableStateFlow(DiagnosticsUiState())
    val diagnosticsState: StateFlow<DiagnosticsUiState> = _diagnosticsState.asStateFlow()

    private var service: ZeroDpiService? = null
    private var serviceStateJob: Job? = null
    private var isBound = false
    private var startWhenConnected = false
    private var startWhenConnectedModeOverride: String? = null

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            isBound = true
            service = (binder as ZeroDpiService.LocalBinder).service()
            serviceStateJob?.cancel()
            serviceStateJob = viewModelScope.launch {
                service?.state()?.collect { state ->
                    _uiState.value = state
                }
            }
            if (startWhenConnected) {
                startWhenConnected = false
                val modeOverride = startWhenConnectedModeOverride
                startWhenConnectedModeOverride = null
                service?.startZeroDpi(modeOverride)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            serviceStateJob?.cancel()
            serviceStateJob = null
            service = null
            isBound = false
            _uiState.value = _uiState.value.copy(status = RuntimeStatus.Stopped)
        }
    }

    init {
        bindService()
        loadRuntimeFiles()
    }

    fun start() {
        viewModelScope.launch {
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

    fun forceStop() {
        service?.forceStopZeroDpi()
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

    suspend fun exportSupportBundle(
        output: OutputStream,
        includePrivateLists: Boolean,
    ) {
        val diagnostics = diagnosticsProvider.collect(
            serviceState = _uiState.value,
            configText = _runtimeFilesState.value.configText,
        )
        runtimeStorage.exportSupportBundle(
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

    fun updateRuntimeFileText(text: String) {
        _runtimeFilesState.update { current ->
            current
                .withText(current.selectedFile, text)
                .copy(
                    dirtyFiles = current.dirtyFiles + current.selectedFile,
                    statusMessage = "Unsaved edits.",
                    errorMessage = null,
                )
        }
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
                    statusMessage = "Unsaved config setting.",
                    errorMessage = null,
                )
        }
    }

    fun saveSelectedRuntimeFile() {
        viewModelScope.launch {
            saveRuntimeFiles(setOf(_runtimeFilesState.value.selectedFile))
        }
    }

    fun importRuntimeFileText(kind: RuntimeFileKind, text: String) {
        _runtimeFilesState.update { current ->
            current
                .withText(kind, text)
                .copy(
                    selectedFile = kind,
                    dirtyFiles = current.dirtyFiles + kind,
                    statusMessage = "Imported ${kind.fileName}. Review and save the file.",
                    errorMessage = null,
                )
        }
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

            if (saveRuntimeFiles(_runtimeFilesState.value.dirtyFiles)) {
                startService(mode)
            }
        }
    }

    fun resetSelectedRuntimeFileToDefaults() {
        val selectedFile = _runtimeFilesState.value.selectedFile
        viewModelScope.launch {
            _runtimeFilesState.update {
                it.copy(isSaving = true, statusMessage = null, errorMessage = null)
            }
            runCatching {
                runtimeStorage.resetToDefaults(selectedFile)
            }.onSuccess { defaultText ->
                _runtimeFilesState.update { current ->
                    current
                        .withText(selectedFile, defaultText)
                        .copy(
                            dirtyFiles = current.dirtyFiles - selectedFile,
                            isSaving = false,
                            statusMessage = "Reset ${selectedFile.fileName} to defaults.",
                            errorMessage = null,
                        )
                }
            }.onFailure { error ->
                _runtimeFilesState.update {
                    it.copy(
                        isSaving = false,
                        errorMessage = error.message ?: "Failed to reset ${selectedFile.fileName}.",
                    )
                }
            }
        }
    }

    private fun startService(modeOverride: String? = null) {
        val intent = Intent(appContext, ZeroDpiService::class.java)
        startWhenConnected = true
        startWhenConnectedModeOverride = modeOverride
        ContextCompat.startForegroundService(appContext, intent)
        bindService()
        service?.let {
            startWhenConnected = false
            startWhenConnectedModeOverride = null
            it.startZeroDpi(modeOverride)
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
            _runtimeFilesState.update {
                it.copy(isLoading = true, errorMessage = null)
            }
            runCatching {
                runtimeStorage.readAll()
            }.onSuccess { contents ->
                _runtimeFilesState.value = RuntimeFilesUiState(
                    runtimeDir = contents.files.runtimeDir.absolutePath,
                    configText = contents.configText,
                    sniListText = contents.sniListText,
                    ipListText = contents.ipListText,
                    configEditor = ZeroDpiConfigToml.analyze(contents.configText),
                    isLoading = false,
                    statusMessage = "Runtime files loaded.",
                )
                refreshDiagnostics()
            }.onFailure { error ->
                _runtimeFilesState.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = error.message ?: "Failed to load runtime files.",
                    )
                }
                refreshDiagnostics()
            }
        }
    }

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

    private suspend fun saveRuntimeFiles(filesToSave: Set<RuntimeFileKind>): Boolean {
        if (filesToSave.isEmpty()) {
            return true
        }

        val snapshot = _runtimeFilesState.value
        _runtimeFilesState.update {
            it.copy(isSaving = true, statusMessage = null, errorMessage = null)
        }

        return runCatching {
            filesToSave.forEach { kind ->
                runtimeStorage.save(kind, snapshot.textFor(kind))
            }
        }.fold(
            onSuccess = {
                _runtimeFilesState.update { current ->
                    current.copy(
                        dirtyFiles = current.dirtyFiles - filesToSave,
                        isSaving = false,
                        statusMessage = "Saved ${filesToSave.joinToString { it.fileName }}.",
                    )
                }
                true
            },
            onFailure = { error ->
                _runtimeFilesState.update {
                    it.copy(
                        isSaving = false,
                        errorMessage = error.message ?: "Failed to save runtime files.",
                    )
                }
                false
            },
        )
    }

    override fun onCleared() {
        serviceStateJob?.cancel()
        if (isBound) {
            runCatching {
                appContext.unbindService(connection)
            }
        }
        super.onCleared()
    }
}
