package dev.zerodpi.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.ui.DashboardScreen
import dev.zerodpi.android.ui.MainViewModel
import dev.zerodpi.android.ui.theme.ZeroDpiTheme
import java.nio.charset.StandardCharsets

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private var pendingImportKind: RuntimeFileKind? = null
    private var pendingExportKind: RuntimeFileKind? = null
    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // Permission denial is non-fatal; Android will still keep service state visible in-app.
        }
    private val importRuntimeFileLauncher =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
            val kind = pendingImportKind
            pendingImportKind = null
            if (kind != null && uri != null) {
                importRuntimeFile(kind, uri)
            }
        }
    private val exportRuntimeFileLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            val kind = pendingExportKind
            pendingExportKind = null
            if (kind != null && uri != null) {
                exportRuntimeFile(kind, uri)
            }
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
                    onConfigFieldChanged = viewModel::updateConfigField,
                    onSaveRuntimeFile = viewModel::saveSelectedRuntimeFile,
                    onResetRuntimeFile = viewModel::resetSelectedRuntimeFileToDefaults,
                    onImportRuntimeFile = ::launchRuntimeFileImport,
                    onExportRuntimeFile = ::launchRuntimeFileExport,
                    onShareRuntimeFile = ::shareRuntimeFile,
                    onRunTestScan = viewModel::runTestScan,
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

    private fun launchRuntimeFileImport(kind: RuntimeFileKind) {
        pendingImportKind = kind
        importRuntimeFileLauncher.launch("text/*")
    }

    private fun launchRuntimeFileExport(kind: RuntimeFileKind) {
        pendingExportKind = kind
        exportRuntimeFileLauncher.launch(kind.fileName)
    }

    private fun importRuntimeFile(kind: RuntimeFileKind, uri: Uri) {
        runCatching {
            contentResolver.openInputStream(uri)?.use { input ->
                input.bufferedReader(StandardCharsets.UTF_8).readText()
            } ?: error("Could not open selected file.")
        }.onSuccess { text ->
            viewModel.importRuntimeFileText(kind, text)
        }.onFailure { error ->
            viewModel.reportRuntimeFileTransferResult(
                successMessage = null,
                errorMessage = error.message ?: "Failed to import ${kind.fileName}.",
            )
        }
    }

    private fun exportRuntimeFile(kind: RuntimeFileKind, uri: Uri) {
        val text = viewModel.runtimeFilesState.value.textFor(kind)
        runCatching {
            contentResolver.openOutputStream(uri)?.use { output ->
                output.bufferedWriter(StandardCharsets.UTF_8).use { writer ->
                    writer.write(text)
                }
            } ?: error("Could not open export destination.")
        }.onSuccess {
            viewModel.reportRuntimeFileTransferResult(
                successMessage = "Exported ${kind.fileName}.",
                errorMessage = null,
            )
        }.onFailure { error ->
            viewModel.reportRuntimeFileTransferResult(
                successMessage = null,
                errorMessage = error.message ?: "Failed to export ${kind.fileName}.",
            )
        }
    }

    private fun shareRuntimeFile(kind: RuntimeFileKind) {
        val text = viewModel.runtimeFilesState.value.textFor(kind)
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, kind.fileName)
            putExtra(Intent.EXTRA_TITLE, kind.fileName)
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(sendIntent, "Share ${kind.fileName}"))
    }
}
