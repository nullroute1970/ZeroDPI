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
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class MainViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val _uiState = MutableStateFlow(ZeroDpiServiceState())
    val uiState: StateFlow<ZeroDpiServiceState> = _uiState.asStateFlow()

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
    }

    fun start() {
        val intent = Intent(appContext, ZeroDpiService::class.java)
        startWhenConnected = true
        ContextCompat.startForegroundService(appContext, intent)
        bindService()
        service?.let {
            startWhenConnected = false
            it.startZeroDpi()
        }
    }

    fun stop() {
        service?.stopZeroDpi()
    }

    private fun bindService() {
        if (isBound) {
            return
        }
        val intent = Intent(appContext, ZeroDpiService::class.java)
        isBound = appContext.bindService(intent, connection, Context.BIND_AUTO_CREATE)
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
