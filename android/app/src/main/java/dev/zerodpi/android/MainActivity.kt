package dev.zerodpi.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import dev.zerodpi.android.ui.DashboardScreen
import dev.zerodpi.android.ui.MainViewModel
import dev.zerodpi.android.ui.theme.ZeroDpiTheme

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // Permission denial is non-fatal; Android will still keep service state visible in-app.
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()

        setContent {
            val state by viewModel.uiState.collectAsState()
            val runtimeFilesState by viewModel.runtimeFilesState.collectAsState()
            ZeroDpiTheme {
                DashboardScreen(
                    state = state,
                    runtimeFilesState = runtimeFilesState,
                    onStart = viewModel::start,
                    onStop = viewModel::stop,
                    onRuntimeFileSelected = viewModel::selectRuntimeFile,
                    onRuntimeFileTextChanged = viewModel::updateRuntimeFileText,
                    onSaveRuntimeFile = viewModel::saveSelectedRuntimeFile,
                    onResetRuntimeFile = viewModel::resetSelectedRuntimeFileToDefaults,
                )
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
