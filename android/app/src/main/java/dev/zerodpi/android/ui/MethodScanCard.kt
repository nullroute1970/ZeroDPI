package dev.zerodpi.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.methodscan.MethodScanEntryModel
import dev.zerodpi.android.methodscan.MethodScanReportModel

@Composable
internal fun MethodScanCard(
    state: MethodScanUiState,
    modifier: Modifier = Modifier,
) {
    when (state.phase) {
        MethodScanPhase.Hidden -> Unit

        MethodScanPhase.Idle -> SectionCard(
            title = stringResource(R.string.method_scan_title),
            modifier = modifier.testTag("method_scan_card"),
        ) {
            Text(stringResource(R.string.method_scan_idle, state.mode.orEmpty()))
        }

        MethodScanPhase.Running -> {
            val completed = state.progress?.completed ?: 0
            val total = state.progress?.total ?: 1
            SectionCard(
                title = stringResource(R.string.method_scan_title),
                modifier = modifier.testTag("method_scan_card"),
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.method_scan_running))
                    LinearProgressIndicator(
                        progress = { (completed.toFloat() / total.coerceAtLeast(1)).coerceIn(0f, 1f) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("method_scan_progress"),
                    )
                    Text(
                        text = stringResource(R.string.method_scan_progress, completed, total),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }

        MethodScanPhase.Completed -> ResultsCard(state.report, modifier)

        is MethodScanPhase.Failed -> SectionCard(
            title = stringResource(R.string.method_scan_title),
            modifier = modifier.testTag("method_scan_card"),
        ) {
            Text(
                text = state.phase.message,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag("method_scan_error"),
            )
        }
    }
}

@Composable
private fun ResultsCard(report: MethodScanReportModel?, modifier: Modifier) {
    if (report == null) return
    SectionCard(
        title = stringResource(R.string.method_scan_title),
        modifier = modifier.testTag("method_scan_card"),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                stringResource(
                    R.string.method_scan_completed,
                    report.methods.size,
                    report.targetSni,
                    report.targetIp,
                    report.targetScore,
                ),
            )
            Row(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.method_scan_column_rank), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(3f)) {
                    Text(stringResource(R.string.method_scan_column_method), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.method_scan_column_success), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.method_scan_column_ttfb), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.method_scan_column_tls), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.method_scan_column_http), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
            }
            report.methods.forEachIndexed { index, entry ->
                MethodScanRow(index, entry)
            }
        }
    }
}

@Composable
private fun MethodScanRow(index: Int, entry: MethodScanEntryModel) {
    val na = stringResource(R.string.method_scan_value_na)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("method_scan_row_${entry.method}"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text((index + 1).toString(), style = MaterialTheme.typography.bodySmall)
        }
        Column(modifier = Modifier.weight(3f)) {
            Text(entry.method, style = MaterialTheme.typography.bodySmall)
            entry.lastError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall) }
        }
        Column(modifier = Modifier.weight(2f)) {
            Text("%.0f%%".format(entry.successRate), style = MaterialTheme.typography.bodySmall)
            Text("${entry.samplesOk}/${entry.samplesTotal}", style = MaterialTheme.typography.labelSmall)
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.avgTtfbMs?.let { "%.0f ms".format(it) } ?: na, style = MaterialTheme.typography.bodySmall)
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.avgTlsMs?.let { "%.0f ms".format(it) } ?: na, style = MaterialTheme.typography.bodySmall)
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.httpStatus?.toString() ?: na, style = MaterialTheme.typography.bodySmall)
        }
    }
}
