package dev.zerodpi.android.ui

import androidx.annotation.StringRes
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import dev.zerodpi.android.R
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiServiceState
import dev.zerodpi.android.storage.RuntimeFileKind

internal enum class AppDestination(
    @param:StringRes val labelRes: Int,
    val icon: ImageVector,
) {
    Home(R.string.nav_home, Icons.Default.Home),
    Profiles(R.string.nav_profiles, Icons.Default.AccountCircle),
    Configure(R.string.nav_configure, Icons.Default.Settings),
    Logs(R.string.nav_logs, Icons.Default.List),
}

internal enum class ConfigView {
    Basic,
    Advanced,
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    state: ZeroDpiServiceState,
    runtimeFilesState: RuntimeFilesUiState,
    profileState: ProfileUiState,
    diagnosticsState: DiagnosticsUiState,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onForceStop: () -> Unit,
    onCreateProfile: (String) -> Unit,
    onDuplicateActiveProfile: (String) -> Unit,
    onRenameProfile: (String, String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onSelectProfile: (String) -> Unit,
    onProfileRemoteConfigUrlChanged: (String) -> Unit,
    onProfileRemoteSniListUrlChanged: (String) -> Unit,
    onProfileRemoteIpListUrlChanged: (String) -> Unit,
    onProfileAutoUpdateChanged: (Boolean) -> Unit,
    onProfileAutoUpdateIntervalChanged: (Int) -> Unit,
    onRunManualProfileUpdate: () -> Unit,
    onRuntimeFileSelected: (RuntimeFileKind) -> Unit,
    onRuntimeFileTextChanged: (RuntimeFileKind, String) -> Unit,
    onConfigFieldChanged: (String, String) -> Unit,
    onResetConfig: () -> Unit,
    onResetRuntimeFile: (RuntimeFileKind) -> Unit,
    onImportRuntimeFile: (RuntimeFileKind) -> Unit,
    onExportRuntimeFile: (RuntimeFileKind) -> Unit,
    onShareRuntimeFile: (RuntimeFileKind) -> Unit,
    onRunTestScan: (RuntimeFileKind) -> Unit,
    onRunRootDiagnostics: () -> Unit,
    onRefreshDiagnostics: () -> Unit,
    onExportSupportBundle: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    var destination by rememberSaveable { mutableStateOf(AppDestination.Home) }
    var listEditor by rememberSaveable { mutableStateOf<RuntimeFileKind?>(null) }
    val profileActionsEnabled = canChangeProfiles(state.status) &&
        !runtimeFilesState.isLoading &&
        !runtimeFilesState.isSaving &&
        !profileState.isProfileLoading &&
        !profileState.isProfileSwitching &&
        !profileState.isRemoteUpdating
    val editorEnabled = !runtimeFilesState.isLoading && !profileState.isRemoteUpdating

    BackHandler(enabled = listEditor != null) {
        listEditor = null
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(
                        text = listEditor?.titleResource()?.let { stringResource(it) }
                            ?: stringResource(destination.labelRes),
                    )
                },
                navigationIcon = {
                    if (listEditor != null) {
                        IconButton(onClick = { listEditor = null }) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = stringResource(R.string.navigate_back),
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
        bottomBar = {
            if (listEditor == null) {
                NavigationBar {
                    AppDestination.entries.forEach { item ->
                        NavigationBarItem(
                            selected = destination == item,
                            onClick = { destination = item },
                            icon = {
                                Icon(
                                    imageVector = item.icon,
                                    contentDescription = null,
                                )
                            },
                            label = { Text(stringResource(item.labelRes)) },
                            modifier = Modifier.testTag("nav_${item.name.lowercase()}"),
                        )
                    }
                }
            }
        },
    ) { padding ->
        val openList: (RuntimeFileKind) -> Unit = { kind ->
            onRuntimeFileSelected(kind)
            listEditor = kind
        }
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            val selectedList = listEditor
            if (selectedList != null) {
                RuntimeListEditorScreen(
                    kind = selectedList,
                    state = runtimeFilesState,
                    actionsEnabled = editorEnabled,
                    onTextChanged = { text -> onRuntimeFileTextChanged(selectedList, text) },
                    onReset = { onResetRuntimeFile(selectedList) },
                    onImport = { onImportRuntimeFile(selectedList) },
                    onExport = { onExportRuntimeFile(selectedList) },
                    onShare = { onShareRuntimeFile(selectedList) },
                    onRunTestScan = { onRunTestScan(selectedList) },
                )
            } else {
                when (destination) {
                    AppDestination.Home -> HomeScreen(
                        serviceState = state,
                        runtimeFilesState = runtimeFilesState,
                        profileState = profileState,
                        onStart = onStart,
                        onStop = onStop,
                        onForceStop = onForceStop,
                        onOpenProfiles = { destination = AppDestination.Profiles },
                        onOpenConfigure = { destination = AppDestination.Configure },
                        onOpenList = openList,
                    )

                    AppDestination.Profiles -> ProfilesScreen(
                        serviceStatus = state.status,
                        profileState = profileState,
                        runtimeFilesState = runtimeFilesState,
                        actionsEnabled = profileActionsEnabled,
                        onCreateProfile = onCreateProfile,
                        onDuplicateActiveProfile = onDuplicateActiveProfile,
                        onRenameProfile = onRenameProfile,
                        onDeleteProfile = onDeleteProfile,
                        onSelectProfile = onSelectProfile,
                        onConfigUrlChanged = onProfileRemoteConfigUrlChanged,
                        onSniListUrlChanged = onProfileRemoteSniListUrlChanged,
                        onIpListUrlChanged = onProfileRemoteIpListUrlChanged,
                        onAutoUpdateChanged = onProfileAutoUpdateChanged,
                        onIntervalHoursChanged = onProfileAutoUpdateIntervalChanged,
                        onRunManualUpdate = onRunManualProfileUpdate,
                    )

                    AppDestination.Configure -> ConfigureScreen(
                        state = runtimeFilesState,
                        enabled = editorEnabled,
                        onConfigFieldChanged = onConfigFieldChanged,
                        onResetConfig = onResetConfig,
                        onOpenList = openList,
                    )

                    AppDestination.Logs -> LiveLogsScreen(
                        serviceState = state,
                    )
                }
            }
        }
    }
}

private fun RuntimeFileKind.titleResource(): Int =
    when (this) {
        RuntimeFileKind.Config -> R.string.configure_title
        RuntimeFileKind.SniList -> R.string.list_sni_title
        RuntimeFileKind.IpList -> R.string.list_ip_title
    }

internal fun canChangeProfiles(status: RuntimeStatus): Boolean =
    when (status) {
        RuntimeStatus.Stopped,
        RuntimeStatus.Failed,
        -> true

        RuntimeStatus.Starting,
        RuntimeStatus.Scanning,
        RuntimeStatus.Running,
        RuntimeStatus.Stopping,
        -> false
    }
