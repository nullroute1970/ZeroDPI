package dev.zerodpi.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiServiceState

@Composable
fun DashboardScreen(
    state: ZeroDpiServiceState,
    onStart: () -> Unit,
    onStop: () -> Unit,
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
            StatusPanel(state = state, onStart = onStart, onStop = onStop)
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
                    -> Button(onClick = onStart) {
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
