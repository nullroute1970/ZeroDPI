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

data class RuntimeFilesUiState(
    val selectedFile: RuntimeFileKind = RuntimeFileKind.Config,
    val runtimeDir: String = "",
    val configText: String = "",
    val sniListText: String = "",
    val ipListText: String = "",
    val dirtyFiles: Set<RuntimeFileKind> = emptySet(),
    val isLoading: Boolean = true,
    val isSaving: Boolean = false,
    val statusMessage: String? = null,
    val errorMessage: String? = null,
) {
    val selectedText: String
        get() = textFor(selectedFile)

    fun textFor(kind: RuntimeFileKind): String =
        when (kind) {
            RuntimeFileKind.Config -> configText
            RuntimeFileKind.SniList -> sniListText
            RuntimeFileKind.IpList -> ipListText
        }

    fun withText(kind: RuntimeFileKind, text: String): RuntimeFilesUiState =
        when (kind) {
            RuntimeFileKind.Config -> copy(configText = text)
            RuntimeFileKind.SniList -> copy(sniListText = text)
            RuntimeFileKind.IpList -> copy(ipListText = text)
        }
}

class MainViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val runtimeStorage = RuntimeStorage(appContext)
    private val _uiState = MutableStateFlow(ZeroDpiServiceState())
    val uiState: StateFlow<ZeroDpiServiceState> = _uiState.asStateFlow()
    private val _runtimeFilesState = MutableStateFlow(RuntimeFilesUiState())
    val runtimeFilesState: StateFlow<RuntimeFilesUiState> = _runtimeFilesState.asStateFlow()

    private var service: ZeroDpiService? = null
    private var serviceStateJob: Job? = null
    private var isBound = false
    private var startWhenConnected = false

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
                service?.startZeroDpi()
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
            if (saveRuntimeFiles(_runtimeFilesState.value.dirtyFiles)) {
                startService()
            }
        }
    }

    fun stop() {
        service?.stopZeroDpi()
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

    fun saveSelectedRuntimeFile() {
        viewModelScope.launch {
            saveRuntimeFiles(setOf(_runtimeFilesState.value.selectedFile))
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

    private fun startService() {
        val intent = Intent(appContext, ZeroDpiService::class.java)
        startWhenConnected = true
        ContextCompat.startForegroundService(appContext, intent)
        bindService()
        service?.let {
            startWhenConnected = false
            it.startZeroDpi()
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
                    isLoading = false,
                    statusMessage = "Runtime files loaded.",
                )
            }.onFailure { error ->
                _runtimeFilesState.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = error.message ?: "Failed to load runtime files.",
                    )
                }
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
