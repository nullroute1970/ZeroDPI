package dev.zerodpi.android.ui

import android.os.SystemClock
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
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
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiServiceState
import dev.zerodpi.android.storage.RuntimeFileKind
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

@Composable
internal fun HomeScreen(
    serviceState: ZeroDpiServiceState,
    runtimeFilesState: RuntimeFilesUiState,
    profileState: ProfileUiState,
    methodScanState: MethodScanUiState,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onForceStop: () -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenConfigure: () -> Unit,
    onOpenList: (RuntimeFileKind) -> Unit,
) {
    val canStart = runtimeFilesState.canStart &&
        !runtimeFilesState.isLoading &&
        !runtimeFilesState.isSaving &&
        !profileState.isRemoteUpdating
    val blockingList = blockingListKind(runtimeFilesState)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .testTag("screen_home")
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        RuntimeStatusCard(
            state = serviceState,
            canStart = canStart,
            onStart = onStart,
            onStop = onStop,
            onForceStop = onForceStop,
        )

        MethodScanCard(state = methodScanState)

        ActiveProfileCard(
            profileState = profileState,
            runtimeFilesState = runtimeFilesState,
            onOpenProfiles = onOpenProfiles,
        )

        if (!canStart) {
            ReadinessCard(
                state = runtimeFilesState,
                profileState = profileState,
                blockingList = blockingList,
                onOpenConfigure = onOpenConfigure,
                onOpenList = onOpenList,
            )
        }

        SectionCard(title = stringResource(R.string.home_runtime_summary)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                MetricTile(
                    label = stringResource(R.string.label_connections),
                    value = serviceState.connectionCount.toString(),
                    modifier = Modifier.weight(1f),
                )
                MetricTile(
                    label = stringResource(R.string.label_relay_bytes),
                    value = formatBytes(serviceState.relayBytes),
                    modifier = Modifier.weight(1f),
                )
            }
            DetailRow(stringResource(R.string.label_mode), serviceState.mode)
            DetailRow(stringResource(R.string.label_bypass_method), serviceState.bypassMethod)
            DetailRow(stringResource(R.string.label_listener), serviceState.listener)
            DetailRow(stringResource(R.string.label_active_target), serviceState.activeTarget)
            DetailRow(
                stringResource(R.string.label_target_score),
                serviceState.activeTargetScore?.toString()
                    ?: stringResource(R.string.value_not_available),
            )
            DetailRow(
                stringResource(R.string.label_next_scan),
                nextScanCountdown(serviceState.nextScanAtElapsedRealtimeMs),
            )
        }
    }
}

@Composable
private fun ActiveProfileCard(
    profileState: ProfileUiState,
    runtimeFilesState: RuntimeFilesUiState,
    onOpenProfiles: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.extraLarge,
        color = MaterialTheme.colorScheme.secondaryContainer,
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
                Icon(Icons.Default.AccountCircle, contentDescription = null)
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.home_active_profile),
                        style = MaterialTheme.typography.labelLarge,
                    )
                    Text(
                        text = profileState.activeProfileName,
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.semantics { heading() },
                    )
                }
            }
            if (runtimeFilesState.dirtyFiles.isNotEmpty() || runtimeFilesState.isSaving) {
                InlineMessage(stringResource(R.string.configure_saving))
            }
            profileState.lastProfileError?.let { InlineMessage(it, error = true) }
            OutlinedButton(
                onClick = onOpenProfiles,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.home_open_profiles))
            }
        }
    }
}

@Composable
private fun MetricTile(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = label,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelMedium,
            )
        }
    }
}

@Composable
private fun RuntimeStatusCard(
    state: ZeroDpiServiceState,
    canStart: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onForceStop: () -> Unit,
) {
    val statusColor = when (state.status) {
        RuntimeStatus.Running -> MaterialTheme.colorScheme.primary
        RuntimeStatus.Failed -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurface
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.extraLarge,
        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                text = stringResource(R.string.home_status),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = if (state.status == RuntimeStatus.Failed) {
                        Icons.Default.Error
                    } else {
                        Icons.Default.CheckCircle
                    },
                    contentDescription = null,
                    tint = statusColor,
                )
                Text(
                    text = statusLabel(state.status),
                    style = MaterialTheme.typography.headlineMedium,
                    color = statusColor,
                    fontWeight = FontWeight.Bold,
                )
            }
            if (state.status.isTransient()) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            state.lastError?.let {
                Text(
                    text = "${stringResource(R.string.home_last_error)}: $it",
                    color = MaterialTheme.colorScheme.error,
                )
            }
            when (state.status) {
                RuntimeStatus.Stopped,
                RuntimeStatus.Failed,
                -> Button(
                    onClick = onStart,
                    enabled = canStart,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("runtime_primary_action"),
                ) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                    Text(
                        text = stringResource(R.string.action_start),
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }

                RuntimeStatus.Starting,
                RuntimeStatus.Scanning,
                RuntimeStatus.Running,
                RuntimeStatus.Restarting,
                RuntimeStatus.Choosing,
                -> OutlinedButton(
                    onClick = onStop,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("runtime_primary_action"),
                ) {
                    Icon(Icons.Default.Stop, contentDescription = null)
                    Text(
                        text = stringResource(R.string.action_stop),
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }

                RuntimeStatus.Stopping -> {
                    OutlinedButton(
                        onClick = {},
                        enabled = false,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.action_stopping))
                    }
                    if (state.forceStopAvailable) {
                        Button(
                            onClick = onForceStop,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.action_force_stop))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ReadinessCard(
    state: RuntimeFilesUiState,
    profileState: ProfileUiState,
    blockingList: RuntimeFileKind?,
    onOpenConfigure: () -> Unit,
    onOpenList: (RuntimeFileKind) -> Unit,
) {
    SectionCard(title = stringResource(R.string.home_needs_attention)) {
        when {
            state.isLoading -> InlineMessage(stringResource(R.string.list_loading))
            state.isSaving -> InlineMessage(stringResource(R.string.configure_saving))
            profileState.isRemoteUpdating -> InlineMessage(stringResource(R.string.profiles_updating))
            state.configEditor.issues.isNotEmpty() -> {
                InlineMessage(
                    stringResource(
                        R.string.configure_errors,
                        state.configEditor.issues.size,
                    ),
                    error = true,
                )
                Button(
                    onClick = onOpenConfigure,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.home_open_configure))
                }
            }

            blockingList != null -> {
                val issues = state.validationFor(blockingList)?.issues.orEmpty()
                InlineMessage(
                    stringResource(R.string.configure_list_errors, issues.size),
                    error = true,
                )
                Button(
                    onClick = { onOpenList(blockingList) },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.home_open_list))
                }
            }

            else -> InlineMessage(stringResource(R.string.home_needs_attention), error = true)
        }
    }
}

@Composable
private fun nextScanCountdown(deadlineElapsedRealtimeMs: Long?): String {
    var nowElapsedRealtimeMs by remember(deadlineElapsedRealtimeMs) {
        mutableLongStateOf(SystemClock.elapsedRealtime())
    }
    LaunchedEffect(deadlineElapsedRealtimeMs) {
        while (isActive && deadlineElapsedRealtimeMs != null) {
            nowElapsedRealtimeMs = SystemClock.elapsedRealtime()
            delay(1_000)
        }
    }

    val deadline = deadlineElapsedRealtimeMs
        ?: return stringResource(R.string.next_scan_not_scheduled)
    if (deadline <= nowElapsedRealtimeMs) {
        return stringResource(R.string.next_scan_in_progress)
    }

    val totalSeconds = (deadline - nowElapsedRealtimeMs + 999L) / 1_000L
    val hours = totalSeconds / 3_600L
    val minutes = totalSeconds % 3_600L / 60L
    val seconds = totalSeconds % 60L
    return if (hours > 0) {
        "$hours:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}"
    } else {
        "$minutes:${seconds.toString().padStart(2, '0')}"
    }
}

@Composable
internal fun statusLabel(status: RuntimeStatus): String =
    stringResource(
        when (status) {
            RuntimeStatus.Stopped -> R.string.status_stopped
            RuntimeStatus.Starting -> R.string.status_starting
            RuntimeStatus.Scanning -> R.string.status_scanning
            RuntimeStatus.Running -> R.string.status_running
            RuntimeStatus.Restarting -> R.string.status_restarting
            RuntimeStatus.Choosing -> R.string.status_choosing
            RuntimeStatus.Stopping -> R.string.status_stopping
            RuntimeStatus.Failed -> R.string.status_failed
        },
    )

private fun blockingListKind(state: RuntimeFilesUiState): RuntimeFileKind? =
    when (state.configEditor.valueFor("MODE")) {
        "sni_scan",
        "sni_spoof",
        "proxy_scan",
        "sni_method_scan",
        -> RuntimeFileKind.SniList.takeIf { !state.sniListValidation.isValid }

        "ip_scan",
        "ip_bypass",
        "ip_bypass_plus",
        "ip_method_scan",
        -> RuntimeFileKind.IpList.takeIf { !state.ipListValidation.isValid }

        else -> null
    }
