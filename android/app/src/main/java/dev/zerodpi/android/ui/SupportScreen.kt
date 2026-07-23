package dev.zerodpi.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.service.ZeroDpiServiceState

@Composable
internal fun SupportScreen(
    serviceState: ZeroDpiServiceState,
    runtimeFilesState: RuntimeFilesUiState,
    diagnosticsState: DiagnosticsUiState,
    onRunRootDiagnostics: () -> Unit,
    onRefreshDiagnostics: () -> Unit,
    onExportSupportBundle: (Boolean) -> Unit,
) {
    var includePrivateLists by rememberSaveable { mutableStateOf(false) }
    val diagnostics = diagnosticsState.diagnostics

    Column(
        modifier = Modifier
            .fillMaxSize()
            .testTag("screen_support")
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionCard(title = stringResource(R.string.support_diagnostics)) {
            DetailRow(stringResource(R.string.label_app_version), diagnostics.appVersion)
            DetailRow(stringResource(R.string.label_zerodpi_version), diagnostics.zeroDpiVersion)
            DetailRow(stringResource(R.string.label_abi), diagnostics.abi)
            DetailRow(stringResource(R.string.label_android), diagnostics.androidVersion)
            DetailRow(stringResource(R.string.label_root), serviceState.rootStatus.label)
            DetailRow(
                stringResource(R.string.label_firewall),
                diagnostics.firewallBackendAvailability,
            )
            DetailRow(
                stringResource(R.string.configure_title),
                if (runtimeFilesState.configEditor.canStart) {
                    stringResource(R.string.configure_valid)
                } else {
                    stringResource(
                        R.string.configure_errors,
                        runtimeFilesState.configEditor.issues.size,
                    )
                },
            )
            DetailRow(
                stringResource(R.string.label_last_exit),
                serviceState.lastExitCode?.toString() ?: "None",
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = onRefreshDiagnostics,
                    enabled = !diagnosticsState.isRefreshing,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = null)
                    Text(
                        stringResource(R.string.action_refresh),
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
                OutlinedButton(
                    onClick = onRunRootDiagnostics,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.BugReport, contentDescription = null)
                    Text(
                        stringResource(R.string.action_run_root_diagnostics),
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.support_include_private))
                    InlineMessage(
                        stringResource(R.string.support_include_private_description),
                    )
                }
                Switch(
                    checked = includePrivateLists,
                    onCheckedChange = { includePrivateLists = it },
                )
            }
            Button(
                onClick = { onExportSupportBundle(includePrivateLists) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.FileDownload, contentDescription = null)
                Text(
                    stringResource(R.string.action_export_bundle),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            diagnosticsState.statusMessage?.let { InlineMessage(it) }
            diagnosticsState.errorMessage?.let { InlineMessage(it, error = true) }
        }

        ExpandableSectionCard(
            title = stringResource(R.string.support_runtime_details),
            testTag = "runtime_details",
        ) {
            DetailRow(stringResource(R.string.label_mode), serviceState.mode)
            DetailRow(stringResource(R.string.label_bypass_method), serviceState.bypassMethod)
            DetailRow(stringResource(R.string.label_listener), serviceState.listener)
            DetailRow(stringResource(R.string.label_active_target), serviceState.activeTarget)
            serviceState.activeTargetScore?.let {
                DetailRow("Target score", it.toString())
            }
            DetailRow(
                stringResource(R.string.label_connections),
                serviceState.connectionCount.toString(),
            )
            DetailRow(
                stringResource(R.string.label_relay_bytes),
                formatBytes(serviceState.relayBytes),
            )
            if (runtimeFilesState.runtimeDir.isNotBlank()) {
                DetailRow(
                    stringResource(R.string.label_storage_path),
                    runtimeFilesState.runtimeDir,
                )
            }
        }

        ExpandableSectionCard(
            title = stringResource(R.string.support_logs),
            initiallyExpanded = serviceState.recentLogs.isNotEmpty(),
            testTag = "runtime_logs",
        ) {
            if (serviceState.recentLogs.isEmpty()) {
                InlineMessage(stringResource(R.string.support_no_logs))
            } else {
                SelectionContainer {
                    Text(
                        text = serviceState.recentLogs.joinToString("\n"),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }
}
