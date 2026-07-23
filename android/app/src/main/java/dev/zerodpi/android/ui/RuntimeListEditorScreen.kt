package dev.zerodpi.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.list.RuntimeListValidation
import dev.zerodpi.android.storage.RuntimeFileKind

@Composable
internal fun RuntimeListEditorScreen(
    kind: RuntimeFileKind,
    state: RuntimeFilesUiState,
    actionsEnabled: Boolean,
    onTextChanged: (String) -> Unit,
    onReset: () -> Unit,
    onImport: () -> Unit,
    onExport: () -> Unit,
    onShare: () -> Unit,
    onRunTestScan: () -> Unit,
) {
    val validation = state.validationFor(kind) ?: return
    val actionEnabled = actionsEnabled && !state.isSaving
    var menuExpanded by rememberSaveable { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .testTag("screen_list_${kind.name.lowercase()}")
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        ListValidationSummary(kind = kind, validation = validation)

        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surfaceContainer,
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = kind.fileName,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier
                            .align(Alignment.CenterStart)
                            .padding(end = 48.dp),
                    )
                    Box(modifier = Modifier.align(Alignment.CenterEnd)) {
                        IconButton(
                            onClick = { menuExpanded = true },
                            modifier = Modifier.testTag("list_more_actions"),
                        ) {
                            Icon(
                                Icons.Default.MoreVert,
                                contentDescription = stringResource(R.string.show_more_actions),
                            )
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false },
                        ) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.action_import)) },
                                leadingIcon = {
                                    Icon(Icons.Default.FileUpload, contentDescription = null)
                                },
                                onClick = {
                                    menuExpanded = false
                                    onImport()
                                },
                                enabled = actionEnabled,
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.action_export)) },
                                leadingIcon = {
                                    Icon(Icons.Default.FileDownload, contentDescription = null)
                                },
                                onClick = {
                                    menuExpanded = false
                                    onExport()
                                },
                                enabled = actionEnabled,
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.action_share)) },
                                leadingIcon = {
                                    Icon(Icons.Default.Share, contentDescription = null)
                                },
                                onClick = {
                                    menuExpanded = false
                                    onShare()
                                },
                                enabled = actionEnabled,
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.action_reset)) },
                                leadingIcon = {
                                    Icon(Icons.Default.Refresh, contentDescription = null)
                                },
                                onClick = {
                                    menuExpanded = false
                                    onReset()
                                },
                                enabled = actionEnabled,
                            )
                        }
                    }
                }
                if (state.isLoading) {
                    InlineMessage(stringResource(R.string.list_loading))
                } else {
                    OutlinedTextField(
                        value = state.textFor(kind),
                        onValueChange = onTextChanged,
                        enabled = actionsEnabled,
                        isError = validation.issues.isNotEmpty(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 320.dp, max = 540.dp)
                            .testTag("list_editor"),
                        textStyle = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                        ),
                        minLines = 14,
                    )
                }
            }
        }

        Button(
            onClick = onRunTestScan,
            enabled = actionEnabled && state.configEditor.canStart && validation.isValid,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("list_test_scan"),
        ) {
            Icon(Icons.Default.PlayArrow, contentDescription = null)
            Text(
                stringResource(R.string.action_run_test_scan),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
        if (kind in state.dirtyFiles || state.isSaving) {
            InlineMessage(stringResource(R.string.list_saving))
        }
        state.statusMessage?.let { InlineMessage(it) }
        state.errorMessage?.let { InlineMessage(it, error = true) }
    }
}

@Composable
private fun ListValidationSummary(
    kind: RuntimeFileKind,
    validation: RuntimeListValidation,
) {
    SectionCard(
        title = if (validation.isValid) {
            stringResource(R.string.list_valid, validation.activeEntries)
        } else {
            stringResource(R.string.list_invalid, validation.issues.size)
        },
    ) {
        InlineMessage(
            stringResource(
                if (kind == RuntimeFileKind.SniList) {
                    R.string.list_sni_help
                } else {
                    R.string.list_ip_help
                },
            ),
        )
        validation.warnings.forEach { InlineMessage(it) }
        validation.issues.take(5).forEach { issue ->
            InlineMessage(
                "Line ${issue.lineNumber}: ${issue.entry} — ${issue.message}",
                error = true,
            )
        }
        if (validation.issues.size > 5) {
            InlineMessage("+ ${validation.issues.size - 5} more errors", error = true)
        }
    }
}
