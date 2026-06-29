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
import androidx.lifecycle.lifecycleScope
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.ui.DashboardScreen
import dev.zerodpi.android.ui.MainViewModel
import dev.zerodpi.android.ui.theme.ZeroDpiTheme
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private var pendingImportKind: RuntimeFileKind? = null
    private var pendingExportKind: RuntimeFileKind? = null
    private var pendingSupportBundleIncludeLists: Boolean = false
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
    private val exportSupportBundleLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
            val includePrivateLists = pendingSupportBundleIncludeLists
            pendingSupportBundleIncludeLists = false
            if (uri != null) {
                exportSupportBundle(uri, includePrivateLists)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()

        setContent {
            val state by viewModel.uiState.collectAsState()
            val runtimeFilesState by viewModel.runtimeFilesState.collectAsState()
            val diagnosticsState by viewModel.diagnosticsState.collectAsState()
            ZeroDpiTheme {
                DashboardScreen(
                    state = state,
                    runtimeFilesState = runtimeFilesState,
                    diagnosticsState = diagnosticsState,
                    onStart = viewModel::start,
                    onStop = viewModel::stop,
                    onForceStop = viewModel::forceStop,
                    onRuntimeFileSelected = viewModel::selectRuntimeFile,
                    onRuntimeFileTextChanged = viewModel::updateRuntimeFileText,
                    onConfigFieldChanged = viewModel::updateConfigField,
                    onSaveConfig = { viewModel.saveRuntimeFile(RuntimeFileKind.Config) },
                    onResetConfig = { viewModel.resetRuntimeFileToDefaults(RuntimeFileKind.Config) },
                    onSaveRuntimeFile = viewModel::saveRuntimeFile,
                    onResetRuntimeFile = viewModel::resetRuntimeFileToDefaults,
                    onImportRuntimeFile = ::launchRuntimeFileImport,
                    onExportRuntimeFile = ::launchRuntimeFileExport,
                    onShareRuntimeFile = ::shareRuntimeFile,
                    onRunTestScan = viewModel::runTestScan,
                    onRunRootDiagnostics = viewModel::runRootDiagnostics,
                    onRefreshDiagnostics = viewModel::refreshDiagnostics,
                    onExportSupportBundle = ::launchSupportBundleExport,
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

    private fun launchSupportBundleExport(includePrivateLists: Boolean) {
        pendingSupportBundleIncludeLists = includePrivateLists
        exportSupportBundleLauncher.launch("zerodpi-support-bundle.zip")
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

    private fun exportSupportBundle(uri: Uri, includePrivateLists: Boolean) {
        lifecycleScope.launch {
            try {
                contentResolver.openOutputStream(uri)?.use { output ->
                    viewModel.exportSupportBundle(output, includePrivateLists)
                } ?: error("Could not open support bundle destination.")
                viewModel.reportSupportBundleExportResult(
                    successMessage = "Exported support bundle.",
                    errorMessage = null,
                )
            } catch (error: Throwable) {
                viewModel.reportSupportBundleExportResult(
                    successMessage = null,
                    errorMessage = error.message ?: "Failed to export support bundle.",
                )
            }
        }
    }
}
