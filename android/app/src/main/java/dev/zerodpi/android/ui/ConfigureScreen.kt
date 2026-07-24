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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
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
        ConfigReadinessCard(
            state = state,
            enabled = enabled,
            onReset = { showResetDialog = true },
        )

        SingleChoiceSegmentedButtonRow(
            modifier = Modifier.fillMaxWidth(),
        ) {
            ConfigView.entries.forEachIndexed { index, item ->
                SegmentedButton(
                    selected = view == item,
                    onClick = { view = item },
                    shape = SegmentedButtonDefaults.itemShape(
                        index = index,
                        count = ConfigView.entries.size,
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("config_${item.name.lowercase()}"),
                ) {
                    Text(
                        stringResource(
                            if (item == ConfigView.Basic) {
                                R.string.configure_basic
                            } else {
                                R.string.configure_advanced
                            },
                        ),
                    )
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
    val isValid = state.configEditor.canStart
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.extraLarge,
        color = if (isValid) {
            MaterialTheme.colorScheme.primaryContainer
        } else {
            MaterialTheme.colorScheme.errorContainer
        },
        tonalElevation = 2.dp,
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(
                    imageVector = if (isValid) {
                        Icons.Default.CheckCircle
                    } else {
                        Icons.Default.Error
                    },
                    contentDescription = null,
                    tint = if (isValid) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.error
                    },
                )
                Text(
                    text = if (isValid) {
                        stringResource(R.string.configure_valid)
                    } else {
                        stringResource(R.string.configure_errors, state.configEditor.issues.size)
                    },
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.semantics { heading() },
                )
            }
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
