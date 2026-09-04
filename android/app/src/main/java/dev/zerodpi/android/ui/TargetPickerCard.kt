package dev.zerodpi.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R

@Composable
internal fun TargetPickerCard(
    state: TargetPickUiState,
    modifier: Modifier = Modifier,
    onRequestPick: () -> Unit = {},
    onCancelPick: () -> Unit = {},
    onChoose: (TargetPickEntryModel) -> Unit = {},
    onClearPin: () -> Unit = {},
) {
    when (state.phase) {
        TargetPickPhase.Hidden -> Unit

        TargetPickPhase.Idle -> IdleCard(state, modifier, onRequestPick, onClearPin)

        TargetPickPhase.Scanning -> ScanningCard(state, modifier, onCancelPick)

        TargetPickPhase.Choosing -> ChoosingCard(state, modifier, onCancelPick, onChoose)

        is TargetPickPhase.Failed -> SectionCard(
            title = stringResource(R.string.target_pick_title),
            modifier = modifier.testTag("target_pick_card"),
        ) {
            Text(
                text = state.phase.message,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag("target_pick_error"),
            )
            OutlinedButton(
                onClick = onRequestPick,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_scan"),
            ) {
                Text(stringResource(R.string.action_scan_choose))
            }
        }
    }
}

@Composable
private fun IdleCard(
    state: TargetPickUiState,
    modifier: Modifier,
    onRequestPick: () -> Unit,
    onClearPin: () -> Unit,
) {
    SectionCard(
        title = stringResource(R.string.target_pick_title),
        modifier = modifier.testTag("target_pick_card"),
    ) {
        val pin = state.pin
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (pin == null) {
                Text(stringResource(R.string.target_pick_idle_no_pin))
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(
                            if (pin.sni.isNullOrBlank()) {
                                R.string.target_pick_pinned_ip
                            } else {
                                R.string.target_pick_pinned_sni
                            },
                            pin.sni ?: pin.ip,
                            pin.ip,
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                    )
                    IconButton(
                        onClick = onClearPin,
                        modifier = Modifier.testTag("target_pick_clear"),
                    ) {
                        Icon(
                            Icons.Default.Delete,
                            contentDescription = stringResource(R.string.action_clear_pin),
                        )
                    }
                }
            }
            OutlinedButton(
                onClick = onRequestPick,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_scan"),
            ) {
                Icon(Icons.Default.Search, contentDescription = null)
                Text(
                    stringResource(R.string.action_scan_choose),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun ScanningCard(
    state: TargetPickUiState,
    modifier: Modifier,
    onCancelPick: () -> Unit,
) {
    val completed = state.progress?.completed ?: 0
    val total = state.progress?.total ?: 1
    SectionCard(
        title = stringResource(R.string.target_pick_title),
        modifier = modifier.testTag("target_pick_card"),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.target_pick_scanning))
            LinearProgressIndicator(
                progress = { (completed.toFloat() / total.coerceAtLeast(1)).coerceIn(0f, 1f) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_progress"),
            )
            Text(
                text = stringResource(R.string.target_pick_progress, completed, total),
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(
                onClick = onCancelPick,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_cancel"),
            ) {
                Icon(Icons.Default.Close, contentDescription = null)
                Text(stringResource(R.string.action_cancel), modifier = Modifier.padding(start = 8.dp))
            }
        }
    }
}

@Composable
private fun ChoosingCard(
    state: TargetPickUiState,
    modifier: Modifier,
    onCancelPick: () -> Unit,
    onChoose: (TargetPickEntryModel) -> Unit,
) {
    SectionCard(
        title = stringResource(R.string.target_pick_title),
        modifier = modifier.testTag("target_pick_card"),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.target_pick_choose_prompt))
            Row(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.target_pick_column_rank),
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
                Column(modifier = Modifier.weight(4f)) {
                    Text(
                        stringResource(R.string.target_pick_column_target),
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(
                        stringResource(R.string.target_pick_column_score),
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(
                        stringResource(R.string.target_pick_column_latency),
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
            state.entries.orEmpty().forEachIndexed { index, entry ->
                PickRow(
                    index = index,
                    entry = entry,
                    enabled = entry.score > 0,
                    onChoose = onChoose,
                )
            }
            if (state.entries.orEmpty().isEmpty()) {
                Text(
                    stringResource(R.string.target_pick_no_results),
                    color = MaterialTheme.colorScheme.error,
                )
            }
            OutlinedButton(
                onClick = onCancelPick,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_cancel"),
            ) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    }
}

@Composable
private fun PickRow(
    index: Int,
    entry: TargetPickEntryModel,
    enabled: Boolean,
    onChoose: (TargetPickEntryModel) -> Unit,
) {
    val rowModifier = Modifier
        .fillMaxWidth()
        .testTag("target_pick_row_$index")
        .then(if (enabled) Modifier.clickable { onChoose(entry) } else Modifier)
    Row(
        modifier = rowModifier,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text((index + 1).toString(), style = MaterialTheme.typography.bodySmall)
        }
        Column(modifier = Modifier.weight(4f)) {
            Text(entry.sni ?: entry.ip, style = MaterialTheme.typography.bodySmall)
            if (entry.sni != null) {
                Text(
                    entry.ip,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.score.toString(), style = MaterialTheme.typography.bodySmall)
            if (!enabled) {
                Text(
                    stringResource(R.string.target_pick_row_failed),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(
                entry.tcpLatencyMs?.let { "$it ms" }
                    ?: stringResource(R.string.value_not_available),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
