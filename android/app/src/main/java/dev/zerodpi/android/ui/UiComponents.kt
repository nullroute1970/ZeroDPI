package dev.zerodpi.android.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.config.ConfigEditorState
import dev.zerodpi.android.config.ConfigFieldSchema
import dev.zerodpi.android.config.ConfigFieldType
import dev.zerodpi.android.service.RuntimeStatus

@Composable
internal fun SectionCard(
    title: String,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainer,
        tonalElevation = 1.dp,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.semantics { heading() },
            )
            content()
        }
    }
}

@Composable
internal fun ExpandableSectionCard(
    title: String,
    initiallyExpanded: Boolean = false,
    testTag: String? = null,
    content: @Composable () -> Unit,
) {
    var expanded by rememberSaveable(title) { mutableStateOf(initiallyExpanded) }
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (testTag == null) Modifier else Modifier.testTag(testTag)),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainer,
        tonalElevation = 1.dp,
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, top = 8.dp, bottom = 8.dp, end = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier
                        .weight(1f)
                        .semantics { heading() },
                )
                IconButton(
                    onClick = { expanded = !expanded },
                    modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp),
                ) {
                    Icon(
                        imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (expanded) "Collapse $title" else "Expand $title",
                    )
                }
            }
            AnimatedVisibility(visible = expanded) {
                Column(
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    content()
                }
            }
        }
    }
}

@Composable
internal fun DetailRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            modifier = Modifier.weight(1f),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            text = value,
            modifier = Modifier.weight(1.25f),
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
    }
}

@Composable
internal fun InlineMessage(
    message: String,
    error: Boolean = false,
    modifier: Modifier = Modifier,
) {
    Text(
        text = message,
        modifier = modifier.fillMaxWidth(),
        color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
internal fun ConfigFieldControl(
    field: ConfigFieldSchema,
    editorState: ConfigEditorState,
    enabled: Boolean,
    onChanged: (String, String) -> Unit,
) {
    val value = editorState.valueFor(field.name)
    val issues = editorState.issuesFor(field.name)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("config_field_${field.name}"),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = field.helpText,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
        when (field.type) {
            ConfigFieldType.Boolean -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = field.name,
                        modifier = Modifier.weight(1f),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                    Switch(
                        checked = value.equals("true", ignoreCase = true),
                        onCheckedChange = { onChanged(field.name, it.toString()) },
                        enabled = enabled,
                    )
                }
            }

            ConfigFieldType.Enum -> {
                var expanded by rememberSaveable(field.name) { mutableStateOf(false) }
                Column {
                    OutlinedTextField(
                        value = value,
                        onValueChange = {},
                        readOnly = true,
                        enabled = enabled,
                        isError = issues.isNotEmpty(),
                        label = { Text(field.name) },
                        trailingIcon = {
                            IconButton(onClick = { expanded = true }, enabled = enabled) {
                                Icon(
                                    imageVector = Icons.Default.ExpandMore,
                                    contentDescription = "Choose ${field.name}",
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    DropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false },
                    ) {
                        field.options.forEach { option ->
                            DropdownMenuItem(
                                text = { Text(option) },
                                onClick = {
                                    expanded = false
                                    onChanged(field.name, option)
                                },
                            )
                        }
                    }
                }
            }

            else -> {
                OutlinedTextField(
                    value = value,
                    onValueChange = { onChanged(field.name, it) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = enabled,
                    singleLine = true,
                    isError = issues.isNotEmpty(),
                    label = { Text(field.name) },
                    keyboardOptions = KeyboardOptions(keyboardType = keyboardTypeFor(field.type)),
                )
            }
        }
        if (field.required) {
            InlineMessage(androidx.compose.ui.res.stringResource(R.string.configure_required))
        }
        issues.forEach { issue ->
            InlineMessage(issue.message, error = true)
        }
        if (issues.isEmpty()) {
            Text(
                text = field.validationRule,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}

internal fun RuntimeStatus.isTransient(): Boolean =
    this == RuntimeStatus.Starting ||
        this == RuntimeStatus.Scanning ||
        this == RuntimeStatus.Restarting ||
        this == RuntimeStatus.Stopping

internal fun keyboardTypeFor(type: ConfigFieldType): KeyboardType =
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

internal fun formatBytes(bytes: Long): String =
    when {
        bytes >= 1_048_576 -> "%.1f MiB".format(bytes / 1_048_576.0)
        bytes >= 1_024 -> "%.1f KiB".format(bytes / 1_024.0)
        else -> "$bytes B"
    }
