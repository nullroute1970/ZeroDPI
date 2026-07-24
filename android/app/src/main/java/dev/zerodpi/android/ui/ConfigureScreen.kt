package dev.zerodpi.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.config.ConfigSection
import dev.zerodpi.android.config.ZeroDpiConfigSchema
import dev.zerodpi.android.storage.RuntimeFileKind

private val basicSections = setOf(
    ConfigSection.ProxyListener,
    ConfigSection.OperatingMode,
    ConfigSection.InputFiles,
    ConfigSection.DnsResolution,
    ConfigSection.BypassEngine,
)

@Composable
internal fun ConfigureScreen(
    state: RuntimeFilesUiState,
    enabled: Boolean,
    onConfigFieldChanged: (String, String) -> Unit,
    onResetConfig: () -> Unit,
    onOpenList: (RuntimeFileKind) -> Unit,
) {
    var view by rememberSaveable { mutableStateOf(ConfigView.Basic) }
    var showResetDialog by rememberSaveable { mutableStateOf(false) }
    val sections = when (view) {
        ConfigView.Basic -> ZeroDpiConfigSchema.sections.filter { it in basicSections }
        ConfigView.Advanced -> ZeroDpiConfigSchema.sections.filterNot { it in basicSections }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .testTag("screen_configure")
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (view == ConfigView.Basic) {
                Button(
                    onClick = { view = ConfigView.Basic },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("config_basic"),
                ) {
                    Text(stringResource(R.string.configure_basic))
                }
            } else {
                OutlinedButton(
                    onClick = { view = ConfigView.Basic },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("config_basic"),
                ) {
                    Text(stringResource(R.string.configure_basic))
                }
            }
            if (view == ConfigView.Advanced) {
                Button(
                    onClick = { view = ConfigView.Advanced },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("config_advanced"),
                ) {
                    Text(stringResource(R.string.configure_advanced))
                }
            } else {
                OutlinedButton(
                    onClick = { view = ConfigView.Advanced },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("config_advanced"),
                ) {
                    Text(stringResource(R.string.configure_advanced))
                }
            }
        }
        Text(
            text = stringResource(
                if (view == ConfigView.Basic) {
                    R.string.configure_basic_description
                } else {
                    R.string.configure_advanced_description
                },
            ),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ConfigReadinessCard(
            state = state,
            enabled = enabled,
            onReset = { showResetDialog = true },
        )

        if (view == ConfigView.Basic) {
            CandidateListsCard(
                state = state,
                enabled = enabled,
                onOpenList = onOpenList,
            )
        }

        sections.forEachIndexed { index, section ->
            ExpandableSectionCard(
                title = section.title,
                initiallyExpanded = view == ConfigView.Basic && index == 0,
                testTag = "config_section_${section.name}",
            ) {
                ZeroDpiConfigSchema.fieldsIn(section).forEach { field ->
                    ConfigFieldControl(
                        field = field,
                        editorState = state.configEditor,
                        enabled = enabled,
                        onChanged = onConfigFieldChanged,
                    )
                }
            }
        }

        state.statusMessage?.let { InlineMessage(it) }
        state.errorMessage?.let { InlineMessage(it, error = true) }
    }

    if (showResetDialog) {
        AlertDialog(
            onDismissRequest = { showResetDialog = false },
            title = { Text(stringResource(R.string.configure_reset_title)) },
            text = { Text(stringResource(R.string.configure_reset_message)) },
            confirmButton = {
                Button(
                    onClick = {
                        showResetDialog = false
                        onResetConfig()
                    },
                    enabled = enabled,
                ) {
                    Text(stringResource(R.string.action_reset))
                }
            },
            dismissButton = {
                TextButton(onClick = { showResetDialog = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun ConfigReadinessCard(
    state: RuntimeFilesUiState,
    enabled: Boolean,
    onReset: () -> Unit,
) {
    SectionCard(
        title = if (state.configEditor.canStart) {
            stringResource(R.string.configure_valid)
        } else {
            stringResource(R.string.configure_errors, state.configEditor.issues.size)
        },
    ) {
        InlineMessage(
            message = state.configEditor.rootRequirement.message,
            error = state.configEditor.rootRequirement.requiresRoot,
        )
        state.configEditor.rootRequirement.alternatives.takeIf { it.isNotEmpty() }?.let {
            InlineMessage("Rootless alternatives: ${it.joinToString()}")
        }
        if (state.dirtyFiles.contains(RuntimeFileKind.Config) || state.isSaving) {
            InlineMessage(stringResource(R.string.configure_saving))
        }
        state.configEditor.issues
            .filter { it.fieldName == null }
            .forEach { InlineMessage(it.message, error = true) }
        OutlinedButton(
            onClick = onReset,
            enabled = enabled && !state.isSaving,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Default.Refresh, contentDescription = null)
            Text(
                stringResource(R.string.action_reset),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
    }
}

@Composable
private fun CandidateListsCard(
    state: RuntimeFilesUiState,
    enabled: Boolean,
    onOpenList: (RuntimeFileKind) -> Unit,
) {
    SectionCard(title = stringResource(R.string.configure_lists)) {
        ListSummaryRow(
            kind = RuntimeFileKind.SniList,
            activeEntries = state.sniListValidation.activeEntries,
            issueCount = state.sniListValidation.issues.size,
            enabled = enabled,
            onOpen = onOpenList,
        )
        ListSummaryRow(
            kind = RuntimeFileKind.IpList,
            activeEntries = state.ipListValidation.activeEntries,
            issueCount = state.ipListValidation.issues.size,
            enabled = enabled,
            onOpen = onOpenList,
        )
    }
}

@Composable
private fun ListSummaryRow(
    kind: RuntimeFileKind,
    activeEntries: Int,
    issueCount: Int,
    enabled: Boolean,
    onOpen: (RuntimeFileKind) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(kind.title, fontWeight = FontWeight.Medium)
            Text(
                text = if (issueCount == 0) {
                    stringResource(R.string.configure_entries, activeEntries)
                } else {
                    stringResource(R.string.configure_list_errors, issueCount)
                },
                color = if (issueCount == 0) {
                    MaterialTheme.colorScheme.onSurfaceVariant
                } else {
                    MaterialTheme.colorScheme.error
                },
                style = MaterialTheme.typography.bodySmall,
            )
        }
        OutlinedButton(
            onClick = { onOpen(kind) },
            enabled = enabled,
        ) {
            Icon(Icons.Default.Edit, contentDescription = null)
            Text(
                stringResource(R.string.action_edit),
                modifier = Modifier.padding(start = 6.dp),
            )
        }
    }
}
