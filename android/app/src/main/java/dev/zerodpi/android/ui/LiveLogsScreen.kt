package dev.zerodpi.android.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiServiceState

internal enum class LogLevelFilter {
    All,
    Info,
    Warning,
    Error,
}

private val errorLogKeywords = listOf("error", "fatal", "failed")

@Composable
internal fun LiveLogsScreen(
    serviceState: ZeroDpiServiceState,
    onClearLogs: () -> Unit,
) {
    val logs = serviceState.recentLogs
    val listState = rememberLazyListState()
    var query by rememberSaveable { mutableStateOf("") }
    var levelFilter by rememberSaveable { mutableStateOf(LogLevelFilter.All) }
    var autoScrollPaused by rememberSaveable { mutableStateOf(false) }
    var showClearDialog by rememberSaveable { mutableStateOf(false) }
    val visibleLogs = logs.filter { line -> logMatches(line, query, levelFilter) }

    LaunchedEffect(visibleLogs, autoScrollPaused) {
        if (!autoScrollPaused && visibleLogs.isNotEmpty()) {
            listState.animateScrollToItem(visibleLogs.lastIndex)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .testTag("screen_logs")
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        LogsHeroCard(
            serviceState = serviceState,
            visibleCount = visibleLogs.size,
            totalCount = logs.size,
            autoScrollPaused = autoScrollPaused,
            onToggleAutoScroll = { autoScrollPaused = !autoScrollPaused },
            onClear = { showClearDialog = true },
        )

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("logs_search"),
            singleLine = true,
            label = { Text(stringResource(R.string.logs_search)) },
            leadingIcon = {
                Icon(Icons.Default.Search, contentDescription = null)
            },
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .testTag("logs_filters"),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            LogLevelFilter.entries.forEach { filter ->
                FilterChip(
                    selected = levelFilter == filter,
                    onClick = { levelFilter = filter },
                    label = { Text(filter.label()) },
                    modifier = Modifier.testTag("logs_filter_${filter.name.lowercase()}"),
                )
            }
        }

        when {
            logs.isEmpty() -> LogsEmptyState(
                message = stringResource(R.string.logs_empty),
                modifier = Modifier.weight(1f),
            )

            visibleLogs.isEmpty() -> LogsEmptyState(
                message = stringResource(R.string.logs_no_matches),
                modifier = Modifier.weight(1f),
            )

            else -> Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                shape = MaterialTheme.shapes.extraLarge,
                color = MaterialTheme.colorScheme.surfaceContainerLow,
                tonalElevation = 1.dp,
            ) {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(14.dp)
                        .testTag("runtime_logs"),
                    state = listState,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(visibleLogs) { line ->
                        Text(
                            text = line,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = logLineColor(line),
                        )
                    }
                }
            }
        }
    }

    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            icon = { Icon(Icons.Default.DeleteSweep, contentDescription = null) },
            title = { Text(stringResource(R.string.logs_clear_title)) },
            text = { Text(stringResource(R.string.logs_clear_message)) },
            confirmButton = {
                Button(
                    onClick = {
                        showClearDialog = false
                        onClearLogs()
                    },
                    modifier = Modifier.testTag("logs_clear_confirm"),
                ) {
                    Text(stringResource(R.string.logs_clear_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun LogsHeroCard(
    serviceState: ZeroDpiServiceState,
    visibleCount: Int,
    totalCount: Int,
    autoScrollPaused: Boolean,
    onToggleAutoScroll: () -> Unit,
    onClear: () -> Unit,
) {
    val active = serviceState.status != RuntimeStatus.Stopped &&
        serviceState.status != RuntimeStatus.Failed
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.extraLarge,
        color = if (active) {
            MaterialTheme.colorScheme.tertiaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceContainerHigh
        },
        tonalElevation = 2.dp,
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Surface(
                    shape = MaterialTheme.shapes.large,
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.7f),
                ) {
                    Icon(
                        Icons.Default.Terminal,
                        contentDescription = null,
                        modifier = Modifier.padding(12.dp),
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = statusLabel(serviceState.status),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.semantics { heading() },
                    )
                    Text(
                        text = stringResource(R.string.logs_count, visibleCount, totalCount),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                IconButton(
                    onClick = onClear,
                    modifier = Modifier.testTag("logs_clear"),
                ) {
                    Icon(
                        Icons.Default.DeleteSweep,
                        contentDescription = stringResource(R.string.logs_clear_action),
                    )
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (autoScrollPaused) {
                    Button(
                        onClick = onToggleAutoScroll,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("logs_auto_scroll"),
                    ) {
                        Icon(Icons.Default.PlayArrow, contentDescription = null)
                        Text(
                            stringResource(R.string.logs_resume),
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                } else {
                    OutlinedButton(
                        onClick = onToggleAutoScroll,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("logs_auto_scroll"),
                    ) {
                        Icon(Icons.Default.Pause, contentDescription = null)
                        Text(
                            stringResource(R.string.logs_pause),
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun LogsEmptyState(
    message: String,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.extraLarge,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                Icons.Default.Terminal,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = message,
                modifier = Modifier.padding(top = 12.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

internal fun classifyLogLine(line: String): LogLevelFilter {
    val normalized = line.lowercase()
    return when {
        errorLogKeywords.any(normalized::contains) -> LogLevelFilter.Error
        normalized.contains("warn") -> LogLevelFilter.Warning
        else -> LogLevelFilter.Info
    }
}

internal fun logMatches(
    line: String,
    query: String,
    levelFilter: LogLevelFilter,
): Boolean =
    line.contains(query.trim(), ignoreCase = true) &&
        (levelFilter == LogLevelFilter.All || classifyLogLine(line) == levelFilter)

@Composable
private fun LogLevelFilter.label(): String =
    stringResource(
        when (this) {
            LogLevelFilter.All -> R.string.logs_filter_all
            LogLevelFilter.Info -> R.string.logs_filter_info
            LogLevelFilter.Warning -> R.string.logs_filter_warning
            LogLevelFilter.Error -> R.string.logs_filter_error
        },
    )

@Composable
private fun logLineColor(line: String) =
    when (classifyLogLine(line)) {
        LogLevelFilter.Error -> MaterialTheme.colorScheme.error
        LogLevelFilter.Warning -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.onSurface
    }
