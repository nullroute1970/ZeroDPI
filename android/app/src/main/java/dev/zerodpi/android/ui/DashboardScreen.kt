package dev.zerodpi.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.config.ConfigEditorState
import dev.zerodpi.android.config.ConfigFieldSchema
import dev.zerodpi.android.config.ConfigFieldType
import dev.zerodpi.android.config.ConfigRootImpact
import dev.zerodpi.android.config.ConfigSection
import dev.zerodpi.android.config.ConfigValidationIssue
import dev.zerodpi.android.config.ZeroDpiConfigSchema
import dev.zerodpi.android.list.RuntimeListValidation
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiServiceState
import dev.zerodpi.android.storage.RuntimeFileKind

@Composable
fun DashboardScreen(
    state: ZeroDpiServiceState,
    runtimeFilesState: RuntimeFilesUiState,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onRuntimeFileSelected: (RuntimeFileKind) -> Unit,
    onRuntimeFileTextChanged: (String) -> Unit,
    onConfigFieldChanged: (String, String) -> Unit,
    onSaveRuntimeFile: () -> Unit,
    onResetRuntimeFile: () -> Unit,
    onImportRuntimeFile: (RuntimeFileKind) -> Unit,
    onExportRuntimeFile: (RuntimeFileKind) -> Unit,
    onShareRuntimeFile: (RuntimeFileKind) -> Unit,
    onRunTestScan: (RuntimeFileKind) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier,
        topBar = { ZeroDpiTopBar() },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusPanel(
                state = state,
                canStart = runtimeFilesState.canStart &&
                    !runtimeFilesState.isLoading &&
                    !runtimeFilesState.isSaving,
                onStart = onStart,
                onStop = onStop,
            )
            ConfigSettingsPanel(
                editorState = runtimeFilesState.configEditor,
                enabled = !runtimeFilesState.isLoading && !runtimeFilesState.isSaving,
                onConfigFieldChanged = onConfigFieldChanged,
            )
            RuntimeFilesPanel(
                state = runtimeFilesState,
                onRuntimeFileSelected = onRuntimeFileSelected,
                onRuntimeFileTextChanged = onRuntimeFileTextChanged,
                onSaveRuntimeFile = onSaveRuntimeFile,
                onResetRuntimeFile = onResetRuntimeFile,
                onImportRuntimeFile = onImportRuntimeFile,
                onExportRuntimeFile = onExportRuntimeFile,
                onShareRuntimeFile = onShareRuntimeFile,
                onRunTestScan = onRunTestScan,
            )
            RuntimeDetails(state = state)
            LogsPanel(logs = state.recentLogs)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ZeroDpiTopBar() {
    TopAppBar(
        title = { Text("ZeroDPI") },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    )
}

@Composable
private fun StatusPanel(
    state: ZeroDpiServiceState,
    canStart: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = state.status.name,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.SemiBold,
            )
            state.lastError?.let { error ->
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                when (state.status) {
                    RuntimeStatus.Stopped,
                    RuntimeStatus.Failed,
                    -> Button(onClick = onStart, enabled = canStart) {
                        Text("Start")
                    }

                    RuntimeStatus.Starting,
                    RuntimeStatus.Scanning,
                    RuntimeStatus.Running,
                    RuntimeStatus.Stopping,
                    -> OutlinedButton(
                        onClick = onStop,
                        enabled = state.status != RuntimeStatus.Stopping,
                    ) {
                        Text("Stop")
                    }
                }
            }
        }
    }
}

@Composable
private fun ConfigSettingsPanel(
    editorState: ConfigEditorState,
    enabled: Boolean,
    onConfigFieldChanged: (String, String) -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Config settings", fontWeight = FontWeight.SemiBold)
            Text(
                text = editorState.rootRequirement.message,
                color = if (editorState.rootRequirement.requiresRoot) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
                style = MaterialTheme.typography.bodyMedium,
            )
            if (editorState.rootRequirement.alternatives.isNotEmpty()) {
                Text(
                    text = "Rootless alternatives: ${editorState.rootRequirement.alternatives.joinToString()}",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (editorState.issues.isEmpty()) {
                Text("Config validation passed.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                Text(
                    text = "Config validation errors",
                    color = MaterialTheme.colorScheme.error,
                    fontWeight = FontWeight.Medium,
                )
                editorState.issues.take(MAX_VISIBLE_VALIDATION_ERRORS).forEach { issue ->
                    val prefix = issue.fieldName?.let { "$it: " }.orEmpty()
                    Text(
                        text = "- $prefix${issue.message}",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (editorState.issues.size > MAX_VISIBLE_VALIDATION_ERRORS) {
                    Text(
                        text = "+ ${editorState.issues.size - MAX_VISIBLE_VALIDATION_ERRORS} more errors",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }

    ZeroDpiConfigSchema.sections.forEach { section ->
        ConfigSectionPanel(
            section = section,
            editorState = editorState,
            enabled = enabled,
            onConfigFieldChanged = onConfigFieldChanged,
        )
    }
}

@Composable
private fun ConfigSectionPanel(
    section: ConfigSection,
    editorState: ConfigEditorState,
    enabled: Boolean,
    onConfigFieldChanged: (String, String) -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(section.title, fontWeight = FontWeight.SemiBold)
            ZeroDpiConfigSchema.fieldsIn(section).forEach { field ->
                ConfigFieldControl(
                    schema = field,
                    value = editorState.valueFor(field.name),
                    issues = editorState.issuesFor(field.name),
                    enabled = enabled,
                    onConfigFieldChanged = onConfigFieldChanged,
                )
            }
        }
    }
}

@Composable
private fun ConfigFieldControl(
    schema: ConfigFieldSchema,
    value: String,
    issues: List<ConfigValidationIssue>,
    enabled: Boolean,
    onConfigFieldChanged: (String, String) -> Unit,
) {
    when (schema.type) {
        ConfigFieldType.Boolean -> BooleanConfigField(
            schema = schema,
            value = value.equals("true", ignoreCase = true),
            issues = issues,
            enabled = enabled,
            onConfigFieldChanged = onConfigFieldChanged,
        )

        ConfigFieldType.Enum -> EnumConfigField(
            schema = schema,
            value = value,
            issues = issues,
            enabled = enabled,
            onConfigFieldChanged = onConfigFieldChanged,
        )

        else -> TextConfigField(
            schema = schema,
            value = value,
            issues = issues,
            enabled = enabled,
            onConfigFieldChanged = onConfigFieldChanged,
        )
    }
}

@Composable
private fun BooleanConfigField(
    schema: ConfigFieldSchema,
    value: Boolean,
    issues: List<ConfigValidationIssue>,
    enabled: Boolean,
    onConfigFieldChanged: (String, String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 12.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(schema.name, fontWeight = FontWeight.Medium)
                FieldHelp(schema = schema, issues = issues)
            }
            Switch(
                checked = value,
                onCheckedChange = { onConfigFieldChanged(schema.name, it.toString()) },
                enabled = enabled,
            )
        }
    }
}

@Composable
private fun EnumConfigField(
    schema: ConfigFieldSchema,
    value: String,
    issues: List<ConfigValidationIssue>,
    enabled: Boolean,
    onConfigFieldChanged: (String, String) -> Unit,
) {
    var expanded by remember(schema.name) { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(schema.name, fontWeight = FontWeight.Medium)
        Box {
            OutlinedButton(
                onClick = { expanded = true },
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(value.ifBlank { "Select ${schema.name}" })
            }
            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                schema.options.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(option) },
                        onClick = {
                            expanded = false
                            onConfigFieldChanged(schema.name, option)
                        },
                    )
                }
            }
        }
        FieldHelp(schema = schema, issues = issues)
    }
}

@Composable
private fun TextConfigField(
    schema: ConfigFieldSchema,
    value: String,
    issues: List<ConfigValidationIssue>,
    enabled: Boolean,
    onConfigFieldChanged: (String, String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = { onConfigFieldChanged(schema.name, it) },
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled,
        isError = issues.isNotEmpty(),
        singleLine = true,
        label = { Text(schema.name) },
        keyboardOptions = KeyboardOptions(keyboardType = keyboardTypeFor(schema.type)),
        supportingText = {
            FieldHelp(schema = schema, issues = issues)
        },
    )
}

@Composable
private fun FieldHelp(
    schema: ConfigFieldSchema,
    issues: List<ConfigValidationIssue>,
) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        if (issues.isNotEmpty()) {
            issues.forEach { issue ->
                Text(
                    text = issue.message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        } else {
            Text(
                text = "${schema.helpText} ${schema.validationRule} Default: ${schema.defaultValue}.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (schema.rootImpact != ConfigRootImpact.None) {
            Text(
                text = schema.rootImpact.label,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private fun keyboardTypeFor(type: ConfigFieldType): KeyboardType =
    when (type) {
        ConfigFieldType.UInt8,
        ConfigFieldType.UInt16,
        ConfigFieldType.UInt32,
        ConfigFieldType.UInt64,
        ConfigFieldType.USize,
        -> KeyboardType.Number

        ConfigFieldType.Float -> KeyboardType.Decimal

        else -> KeyboardType.Text
    }

@Composable
private fun RuntimeFilesPanel(
    state: RuntimeFilesUiState,
    onRuntimeFileSelected: (RuntimeFileKind) -> Unit,
    onRuntimeFileTextChanged: (String) -> Unit,
    onSaveRuntimeFile: () -> Unit,
    onResetRuntimeFile: () -> Unit,
    onImportRuntimeFile: (RuntimeFileKind) -> Unit,
    onExportRuntimeFile: (RuntimeFileKind) -> Unit,
    onShareRuntimeFile: (RuntimeFileKind) -> Unit,
    onRunTestScan: (RuntimeFileKind) -> Unit,
) {
    val selectedListValidation = state.selectedListValidation
    val selectedFileIsList = state.selectedFile != RuntimeFileKind.Config
    val actionsEnabled = !state.isLoading && !state.isSaving

    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Runtime files", fontWeight = FontWeight.SemiBold)
            if (state.runtimeDir.isNotBlank()) {
                Text(
                    text = state.runtimeDir,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                RuntimeFileKind.entries.forEach { kind ->
                    val label = if (kind in state.dirtyFiles) {
                        "${kind.title} *"
                    } else {
                        kind.title
                    }
                    if (kind == state.selectedFile) {
                        Button(
                            onClick = { onRuntimeFileSelected(kind) },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(label)
                        }
                    } else {
                        OutlinedButton(
                            onClick = { onRuntimeFileSelected(kind) },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(label)
                        }
                    }
                }
            }
            selectedListValidation?.let { validation ->
                RuntimeListValidationSummary(
                    kind = state.selectedFile,
                    validation = validation,
                )
            }
            if (state.isLoading) {
                Text("Loading runtime files.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                OutlinedTextField(
                    value = state.selectedText,
                    onValueChange = onRuntimeFileTextChanged,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 220.dp, max = 360.dp),
                    enabled = !state.isSaving,
                    isError = selectedListValidation?.issues?.isNotEmpty() == true,
                    label = { Text(state.selectedFile.fileName) },
                    textStyle = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                    ),
                    minLines = 10,
                    maxLines = 18,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = onSaveRuntimeFile,
                    enabled = actionsEnabled,
                ) {
                    Text(if (state.isSaving) "Saving" else "Save")
                }
                OutlinedButton(
                    onClick = onResetRuntimeFile,
                    enabled = actionsEnabled,
                ) {
                    Text("Reset to defaults")
                }
            }
            if (selectedFileIsList) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = { onImportRuntimeFile(state.selectedFile) },
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Import")
                    }
                    OutlinedButton(
                        onClick = { onExportRuntimeFile(state.selectedFile) },
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Export")
                    }
                    OutlinedButton(
                        onClick = { onShareRuntimeFile(state.selectedFile) },
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Share")
                    }
                }
                Button(
                    onClick = { onRunTestScan(state.selectedFile) },
                    enabled = actionsEnabled &&
                        state.configEditor.canStart &&
                        selectedListValidation?.isValid == true,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        when (state.selectedFile) {
                            RuntimeFileKind.SniList -> "Run SNI test scan"
                            RuntimeFileKind.IpList -> "Run IP test scan"
                            RuntimeFileKind.Config -> "Run test scan"
                        },
                    )
                }
            }
            state.statusMessage?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            state.errorMessage?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun RuntimeListValidationSummary(
    kind: RuntimeFileKind,
    validation: RuntimeListValidation,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = when (kind) {
                RuntimeFileKind.SniList -> "One hostname per line. Blank lines and lines starting with # are preserved."
                RuntimeFileKind.IpList -> "One IPv4, IPv6, IPv4 CIDR, or IPv6 CIDR per line. Blank lines and # comments are preserved."
                RuntimeFileKind.Config -> ""
            },
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
        )
        validation.warnings.forEach { warning ->
            Text(
                text = warning,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (validation.issues.isEmpty()) {
            Text(
                text = "${validation.activeEntries} active entries look valid.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
        } else {
            Text(
                text = "${validation.issues.size} invalid entries",
                color = MaterialTheme.colorScheme.error,
                fontWeight = FontWeight.Medium,
            )
            validation.issues.take(MAX_VISIBLE_LIST_ERRORS).forEach { issue ->
                Text(
                    text = "Line ${issue.lineNumber}: ${issue.entry} - ${issue.message}",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (validation.issues.size > MAX_VISIBLE_LIST_ERRORS) {
                Text(
                    text = "+ ${validation.issues.size - MAX_VISIBLE_LIST_ERRORS} more list errors",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun RuntimeDetails(state: ZeroDpiServiceState) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        DetailRow("Root", state.rootStatus)
        DetailRow("Mode", state.mode)
        DetailRow("Bypass", state.bypassMethod)
        DetailRow("Listener", state.listener)
        DetailRow("Active target", state.activeTarget)
        DetailRow("Connections", state.connectionCount.toString())
        DetailRow("Relay bytes", state.relayBytes.toString())
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun LogsPanel(logs: List<String>) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text("Recent logs", fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(2.dp))
            if (logs.isEmpty()) {
                Text("No runtime logs yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                logs.forEach { line ->
                    Text(
                        text = line,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }
}

private const val MAX_VISIBLE_VALIDATION_ERRORS = 6
private const val MAX_VISIBLE_LIST_ERRORS = 6
