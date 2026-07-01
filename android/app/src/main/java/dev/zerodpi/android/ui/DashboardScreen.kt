package dev.zerodpi.android.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
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
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
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
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiServiceState
import dev.zerodpi.android.storage.RuntimeFileKind
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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
    onSaveAndSelectProfile: (String?) -> Unit,
    onDiscardAndSelectProfile: (String?) -> Unit,
    onCancelProfileSwitch: () -> Unit,
    onProfileRemoteConfigUrlChanged: (String) -> Unit,
    onProfileRemoteSniListUrlChanged: (String) -> Unit,
    onProfileRemoteIpListUrlChanged: (String) -> Unit,
    onProfileAutoUpdateChanged: (Boolean) -> Unit,
    onProfileAutoUpdateIntervalChanged: (Int) -> Unit,
    onRunManualProfileUpdate: (Boolean) -> Unit,
    onRuntimeFileSelected: (RuntimeFileKind) -> Unit,
    onRuntimeFileTextChanged: (RuntimeFileKind, String) -> Unit,
    onConfigFieldChanged: (String, String) -> Unit,
    onSaveConfig: () -> Unit,
    onResetConfig: () -> Unit,
    onSaveRuntimeFile: (RuntimeFileKind) -> Unit,
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
    var page by rememberSaveable { mutableStateOf(DashboardPage.Home) }
    val profileActionsEnabled = canChangeProfiles(state.status) &&
        !runtimeFilesState.isLoading &&
        !runtimeFilesState.isSaving &&
        !profileState.isProfileLoading &&
        !profileState.isProfileSwitching &&
        !profileState.isRemoteUpdating
    val runtimeFileActionsEnabled = !runtimeFilesState.isLoading &&
        !runtimeFilesState.isSaving &&
        !profileState.isRemoteUpdating

    BackHandler(enabled = page != DashboardPage.Home) {
        page = DashboardPage.Home
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            ZeroDpiTopBar(
                page = page,
                onNavigateHome = { page = DashboardPage.Home },
                onNavigateSettings = { page = DashboardPage.Settings },
                onNavigateSniList = {
                    onRuntimeFileSelected(RuntimeFileKind.SniList)
                    page = DashboardPage.SniList
                },
                onNavigateIpList = {
                    onRuntimeFileSelected(RuntimeFileKind.IpList)
                    page = DashboardPage.IpList
                },
            )
        },
    ) { padding ->
        when (page) {
            DashboardPage.Home -> {
                Column(
                    modifier = Modifier
                        .padding(padding)
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    ActiveProfileSelectorPanel(
                        serviceStatus = state.status,
                        profileState = profileState,
                        runtimeFilesState = runtimeFilesState,
                        actionsEnabled = profileActionsEnabled,
                        onManageProfiles = { page = DashboardPage.Settings },
                        onSelectProfile = onSelectProfile,
                        onSaveAndSelectProfile = onSaveAndSelectProfile,
                        onDiscardAndSelectProfile = onDiscardAndSelectProfile,
                        onCancelProfileSwitch = onCancelProfileSwitch,
                    )
                    StatusPanel(
                        state = state,
                        canStart = runtimeFilesState.canStart &&
                            !runtimeFilesState.isLoading &&
                            !runtimeFilesState.isSaving &&
                            !profileState.isRemoteUpdating,
                        onStart = onStart,
                        onStop = onStop,
                        onForceStop = onForceStop,
                    )
                    RuntimeDetails(state = state)
                    DiagnosticsPanel(
                        serviceState = state,
                        runtimeFilesState = runtimeFilesState,
                        diagnosticsState = diagnosticsState,
                        onRefreshDiagnostics = onRefreshDiagnostics,
                        onExportSupportBundle = onExportSupportBundle,
                    )
                    LogsPanel(logs = state.recentLogs)
                }
            }

            DashboardPage.Settings -> {
                Column(
                    modifier = Modifier
                        .padding(padding)
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    ProfileManagementPanel(
                        profileState = profileState,
                        runtimeFilesState = runtimeFilesState,
                        actionsEnabled = profileActionsEnabled,
                        onCreateProfile = onCreateProfile,
                        onDuplicateActiveProfile = onDuplicateActiveProfile,
                        onRenameProfile = onRenameProfile,
                        onDeleteProfile = onDeleteProfile,
                    )
                    RemoteUpdatePanel(
                        serviceStatus = state.status,
                        profileState = profileState,
                        runtimeFilesState = runtimeFilesState,
                        actionsEnabled = profileActionsEnabled,
                        onConfigUrlChanged = onProfileRemoteConfigUrlChanged,
                        onSniListUrlChanged = onProfileRemoteSniListUrlChanged,
                        onIpListUrlChanged = onProfileRemoteIpListUrlChanged,
                        onAutoUpdateChanged = onProfileAutoUpdateChanged,
                        onIntervalHoursChanged = onProfileAutoUpdateIntervalChanged,
                        onRunManualUpdate = onRunManualProfileUpdate,
                    )
                    ConfigSettingsPanel(
                        editorState = runtimeFilesState.configEditor,
                        enabled = runtimeFileActionsEnabled,
                        isSaving = runtimeFilesState.isSaving,
                        hasUnsavedConfig = RuntimeFileKind.Config in runtimeFilesState.dirtyFiles,
                        statusMessage = runtimeFilesState.statusMessage,
                        errorMessage = runtimeFilesState.errorMessage,
                        onConfigFieldChanged = onConfigFieldChanged,
                        onSaveConfig = onSaveConfig,
                        onResetConfig = onResetConfig,
                        onRunRootDiagnostics = onRunRootDiagnostics,
                    )
                }
            }

            DashboardPage.SniList -> {
                RuntimeListPage(
                    padding = padding,
                    title = "SNI list",
                    fileKind = RuntimeFileKind.SniList,
                    runtimeFilesState = runtimeFilesState,
                    actionsEnabled = runtimeFileActionsEnabled,
                    onRuntimeFileSelected = onRuntimeFileSelected,
                    onRuntimeFileTextChanged = onRuntimeFileTextChanged,
                    onSaveRuntimeFile = onSaveRuntimeFile,
                    onResetRuntimeFile = onResetRuntimeFile,
                    onImportRuntimeFile = onImportRuntimeFile,
                    onExportRuntimeFile = onExportRuntimeFile,
                    onShareRuntimeFile = onShareRuntimeFile,
                    onRunTestScan = onRunTestScan,
                )
            }

            DashboardPage.IpList -> {
                RuntimeListPage(
                    padding = padding,
                    title = "IP list",
                    fileKind = RuntimeFileKind.IpList,
                    runtimeFilesState = runtimeFilesState,
                    actionsEnabled = runtimeFileActionsEnabled,
                    onRuntimeFileSelected = onRuntimeFileSelected,
                    onRuntimeFileTextChanged = onRuntimeFileTextChanged,
                    onSaveRuntimeFile = onSaveRuntimeFile,
                    onResetRuntimeFile = onResetRuntimeFile,
                    onImportRuntimeFile = onImportRuntimeFile,
                    onExportRuntimeFile = onExportRuntimeFile,
                    onShareRuntimeFile = onShareRuntimeFile,
                    onRunTestScan = onRunTestScan,
                )
            }
        }
    }
}

private enum class DashboardPage(val title: String) {
    Home("ZeroDPI"),
    Settings("Settings"),
    SniList("SNI list"),
    IpList("IP list"),
}

@Composable
private fun RuntimeListPage(
    padding: PaddingValues,
    title: String,
    fileKind: RuntimeFileKind,
    runtimeFilesState: RuntimeFilesUiState,
    actionsEnabled: Boolean,
    onRuntimeFileSelected: (RuntimeFileKind) -> Unit,
    onRuntimeFileTextChanged: (RuntimeFileKind, String) -> Unit,
    onSaveRuntimeFile: (RuntimeFileKind) -> Unit,
    onResetRuntimeFile: (RuntimeFileKind) -> Unit,
    onImportRuntimeFile: (RuntimeFileKind) -> Unit,
    onExportRuntimeFile: (RuntimeFileKind) -> Unit,
    onShareRuntimeFile: (RuntimeFileKind) -> Unit,
    onRunTestScan: (RuntimeFileKind) -> Unit,
) {
    Column(
        modifier = Modifier
            .padding(padding)
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        RuntimeFilesPanel(
            title = title,
            fileKinds = listOf(fileKind),
            state = runtimeFilesState,
            actionsEnabled = actionsEnabled,
            onRuntimeFileSelected = onRuntimeFileSelected,
            onRuntimeFileTextChanged = onRuntimeFileTextChanged,
            onSaveRuntimeFile = onSaveRuntimeFile,
            onResetRuntimeFile = onResetRuntimeFile,
            onImportRuntimeFile = onImportRuntimeFile,
            onExportRuntimeFile = onExportRuntimeFile,
            onShareRuntimeFile = onShareRuntimeFile,
            onRunTestScan = onRunTestScan,
        )
    }
}

@Composable
private fun ActiveProfileSelectorPanel(
    serviceStatus: RuntimeStatus,
    profileState: ProfileUiState,
    runtimeFilesState: RuntimeFilesUiState,
    actionsEnabled: Boolean,
    onManageProfiles: () -> Unit,
    onSelectProfile: (String) -> Unit,
    onSaveAndSelectProfile: (String?) -> Unit,
    onDiscardAndSelectProfile: (String?) -> Unit,
    onCancelProfileSwitch: () -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val pendingProfile = profileState.pendingSwitchProfile
    val dirtyFiles = runtimeFilesState.dirtyFiles
    val canOpenMenu = actionsEnabled && profileState.profiles.isNotEmpty()

    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
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
                    Text("Active profile", fontWeight = FontWeight.SemiBold)
                    Text(
                        text = profileState.activeProfileName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Medium,
                    )
                    if (dirtyFiles.isNotEmpty()) {
                        Text(
                            text = "Unsaved: ${dirtyFiles.joinToString { it.fileName }}",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                Box {
                    Button(
                        onClick = { expanded = true },
                        enabled = canOpenMenu,
                    ) {
                        Text(if (profileState.isProfileSwitching) "Switching" else "Switch")
                    }
                    DropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false },
                    ) {
                        profileState.profiles.forEach { profile ->
                            DropdownMenuItem(
                                text = {
                                    Column {
                                        Text(profile.name)
                                        Text(
                                            text = profile.id,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                    }
                                },
                                onClick = {
                                    expanded = false
                                    onSelectProfile(profile.id)
                                },
                            )
                        }
                    }
                }
            }
            OutlinedButton(
                onClick = onManageProfiles,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Manage profiles")
            }
            if (!canChangeProfiles(serviceStatus)) {
                Text(
                    text = "Stop ZeroDPI before switching profiles.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            pendingProfile?.let { target ->
                Text(
                    text = "Switch to ${target.name} with unsaved edits?",
                    color = MaterialTheme.colorScheme.error,
                    fontWeight = FontWeight.Medium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { onSaveAndSelectProfile(target.id) },
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Save")
                    }
                    OutlinedButton(
                        onClick = { onDiscardAndSelectProfile(target.id) },
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Discard")
                    }
                    TextButton(onClick = onCancelProfileSwitch) {
                        Text("Cancel")
                    }
                }
            }
            profileState.statusMessage?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            profileState.lastProfileError?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun ProfileManagementPanel(
    profileState: ProfileUiState,
    runtimeFilesState: RuntimeFilesUiState,
    actionsEnabled: Boolean,
    onCreateProfile: (String) -> Unit,
    onDuplicateActiveProfile: (String) -> Unit,
    onRenameProfile: (String, String) -> Unit,
    onDeleteProfile: (String) -> Unit,
) {
    var showCreateDialog by remember { mutableStateOf(false) }
    var showDuplicateDialog by remember { mutableStateOf(false) }
    var showRenameDialog by remember { mutableStateOf(false) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    val activeProfile = profileState.activeProfile
    val canDelete = actionsEnabled && profileState.profiles.size > 1
    val storageStatus = when {
        profileState.isRemoteUpdating -> "Updating"
        profileState.isProfileSwitching -> "Switching"
        profileState.isProfileLoading -> "Loading"
        runtimeFilesState.runtimeDir.isBlank() -> "Pending"
        else -> "Ready"
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Profiles", fontWeight = FontWeight.SemiBold)
            DetailRow("Active", profileState.activeProfileName)
            DetailRow("Profile id", profileState.activeProfileId)
            DetailRow("Profiles", profileState.profiles.size.toString())
            DetailRow("Storage", storageStatus)
            if (runtimeFilesState.runtimeDir.isNotBlank()) {
                Text(
                    text = runtimeFilesState.runtimeDir,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { showCreateDialog = true },
                    enabled = actionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Create")
                }
                OutlinedButton(
                    onClick = { showDuplicateDialog = true },
                    enabled = actionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Duplicate")
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { showRenameDialog = true },
                    enabled = actionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Rename")
                }
                OutlinedButton(
                    onClick = { showDeleteDialog = true },
                    enabled = canDelete,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Delete")
                }
            }
            if (profileState.profiles.size <= 1) {
                Text(
                    text = "The last profile cannot be deleted.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }

    if (showCreateDialog) {
        ProfileNameDialog(
            title = "Create profile",
            initialName = uniqueProfileName("New profile", profileState.profiles),
            confirmLabel = "Create",
            onDismiss = { showCreateDialog = false },
            onConfirm = { name ->
                showCreateDialog = false
                onCreateProfile(name)
            },
        )
    }
    if (showDuplicateDialog) {
        ProfileNameDialog(
            title = "Duplicate profile",
            initialName = uniqueProfileName("${profileState.activeProfileName} copy", profileState.profiles),
            confirmLabel = "Duplicate",
            onDismiss = { showDuplicateDialog = false },
            onConfirm = { name ->
                showDuplicateDialog = false
                onDuplicateActiveProfile(name)
            },
        )
    }
    if (showRenameDialog && activeProfile != null) {
        ProfileNameDialog(
            title = "Rename profile",
            initialName = activeProfile.name,
            confirmLabel = "Rename",
            onDismiss = { showRenameDialog = false },
            onConfirm = { name ->
                showRenameDialog = false
                onRenameProfile(activeProfile.id, name)
            },
        )
    }
    if (showDeleteDialog && activeProfile != null) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Delete profile") },
            text = {
                Text("Delete ${activeProfile.name}? This removes that profile's local config and list files.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDeleteDialog = false
                        onDeleteProfile(activeProfile.id)
                    },
                    enabled = canDelete,
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text("Cancel")
                }
            },
        )
    }
}

@Composable
private fun RemoteUpdatePanel(
    serviceStatus: RuntimeStatus,
    profileState: ProfileUiState,
    runtimeFilesState: RuntimeFilesUiState,
    actionsEnabled: Boolean,
    onConfigUrlChanged: (String) -> Unit,
    onSniListUrlChanged: (String) -> Unit,
    onIpListUrlChanged: (String) -> Unit,
    onAutoUpdateChanged: (Boolean) -> Unit,
    onIntervalHoursChanged: (Int) -> Unit,
    onRunManualUpdate: (Boolean) -> Unit,
) {
    var showManualUpdateDialog by remember { mutableStateOf(false) }
    val remote = profileState.profileRemoteSettings
    val remoteValidation = remote.validate()
    val updateValidation = remote.validateForUpdate()
    val remoteFieldsEnabled = !profileState.isProfileLoading && !profileState.isRemoteUpdating
    val updateEnabled = actionsEnabled && updateValidation.isValid
    val dirtyFiles = runtimeFilesState.dirtyFiles
    var intervalText by remember(remote.autoUpdateIntervalHours) {
        mutableStateOf(remote.autoUpdateIntervalHours.toString())
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Remote update", fontWeight = FontWeight.SemiBold)
            RemoteUrlField(
                label = "config.toml URL",
                value = remote.configUrl,
                enabled = remoteFieldsEnabled,
                onValueChange = onConfigUrlChanged,
            )
            RemoteUrlField(
                label = "sni_list.txt URL",
                value = remote.sniListUrl,
                enabled = remoteFieldsEnabled,
                onValueChange = onSniListUrlChanged,
            )
            RemoteUrlField(
                label = "ip_list.txt URL",
                value = remote.ipListUrl,
                enabled = remoteFieldsEnabled,
                onValueChange = onIpListUrlChanged,
            )
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
                    Text("Automatic update", fontWeight = FontWeight.Medium)
                    Text(
                        text = "Remote files overwrite local edits after a successful update.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Switch(
                    checked = remote.autoUpdateEnabled,
                    onCheckedChange = onAutoUpdateChanged,
                    enabled = remoteFieldsEnabled,
                )
            }
            OutlinedTextField(
                value = intervalText,
                onValueChange = { value ->
                    intervalText = value
                    value.toIntOrNull()?.let(onIntervalHoursChanged)
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = remoteFieldsEnabled,
                singleLine = true,
                label = { Text("Automatic update interval hours") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            Text(
                text = "Remote update replaces local config.toml, sni_list.txt, and ip_list.txt for this profile.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
            if (remote.autoUpdateEnabled && dirtyFiles.isNotEmpty()) {
                Text(
                    text = "Unsaved local edits can be overwritten by the next successful auto update.",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (!canChangeProfiles(serviceStatus)) {
                Text(
                    text = "Stop ZeroDPI before updating from remote.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Button(
                onClick = { showManualUpdateDialog = true },
                enabled = updateEnabled,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (profileState.isRemoteUpdating) "Updating" else "Update now")
            }
            if (profileState.isRemoteUpdating) {
                Text(
                    text = "Downloading, validating, and applying remote files.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (remoteValidation.isValid && !updateValidation.isValid) {
                Text(
                    text = "Configure all three valid URLs before running a manual update.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            remoteValidation.errors.forEach { issue ->
                Text(
                    text = issue.message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            remoteValidation.warnings.forEach { issue ->
                Text(
                    text = issue.message,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            DetailRow("Last attempt", formatEpochMs(remote.lastUpdateAttemptEpochMs))
            DetailRow("Last success", formatEpochMs(remote.lastSuccessfulUpdateEpochMs))
            remote.lastUpdateStatus?.let { status ->
                DetailRow("Last update", if (status.successful) "Success" else "Failed")
                if (status.message.isNotBlank()) {
                    Text(
                        text = status.message,
                        color = if (status.successful) {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        } else {
                            MaterialTheme.colorScheme.error
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            profileState.lastProfileError?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.error)
            }
        }
    }

    if (showManualUpdateDialog) {
        AlertDialog(
            onDismissRequest = { showManualUpdateDialog = false },
            title = { Text("Update profile files") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Remote update replaces local config.toml, sni_list.txt, and ip_list.txt for this profile.")
                    if (dirtyFiles.isNotEmpty()) {
                        Text(
                            text = "Unsaved local edits will be discarded.",
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showManualUpdateDialog = false
                        onRunManualUpdate(dirtyFiles.isNotEmpty())
                    },
                    enabled = updateEnabled,
                ) {
                    Text("Update")
                }
            },
            dismissButton = {
                TextButton(onClick = { showManualUpdateDialog = false }) {
                    Text("Cancel")
                }
            },
        )
    }
}

@Composable
private fun RemoteUrlField(
    label: String,
    value: String,
    enabled: Boolean,
    onValueChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled,
        singleLine = true,
        label = { Text(label) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text),
    )
}

@Composable
private fun ProfileNameDialog(
    title: String,
    initialName: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var name by remember(initialName) { mutableStateOf(initialName) }
    val trimmedName = name.trim()
    val nameValidation = ZeroDpiProfile.validateName(trimmedName)
    val canConfirm = nameValidation.isValid

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Profile name") },
                    isError = !canConfirm,
                )
                nameValidation.errors.forEach { issue ->
                    Text(
                        text = issue.message,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(trimmedName) },
                enabled = canConfirm,
            ) {
                Text(confirmLabel)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ZeroDpiTopBar(
    page: DashboardPage,
    onNavigateHome: () -> Unit,
    onNavigateSettings: () -> Unit,
    onNavigateSniList: () -> Unit,
    onNavigateIpList: () -> Unit,
) {
    var menuExpanded by remember { mutableStateOf(false) }

    TopAppBar(
        title = {
            Text(page.title)
        },
        navigationIcon = {
            if (page != DashboardPage.Home) {
                TextButton(onClick = onNavigateHome) {
                    Text("Back")
                }
            }
        },
        actions = {
            Box {
                TextButton(onClick = { menuExpanded = true }) {
                    Text("\u2630 Menu")
                }
                DropdownMenu(
                    expanded = menuExpanded,
                    onDismissRequest = { menuExpanded = false },
                ) {
                    DropdownMenuItem(
                        text = { Text("Settings") },
                        onClick = {
                            menuExpanded = false
                            onNavigateSettings()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("SNI list") },
                        onClick = {
                            menuExpanded = false
                            onNavigateSniList()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("IP list") },
                        onClick = {
                            menuExpanded = false
                            onNavigateIpList()
                        },
                    )
                }
            }
        },
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
    onForceStop: () -> Unit,
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
                    -> OutlinedButton(
                        onClick = onStop,
                        enabled = true,
                    ) {
                        Text("Stop")
                    }

                    RuntimeStatus.Stopping -> {
                        OutlinedButton(onClick = onStop, enabled = false) {
                            Text("Stopping")
                        }
                        if (state.forceStopAvailable) {
                            Button(onClick = onForceStop) {
                                Text("Force stop")
                            }
                        }
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
    isSaving: Boolean,
    hasUnsavedConfig: Boolean,
    statusMessage: String?,
    errorMessage: String?,
    onConfigFieldChanged: (String, String) -> Unit,
    onSaveConfig: () -> Unit,
    onResetConfig: () -> Unit,
    onRunRootDiagnostics: () -> Unit,
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
            Text(
                text = "Root diagnostics invoke su to check UID 0, firewall commands, and NFQUEUE hints.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(
                onClick = onRunRootDiagnostics,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Run root diagnostics")
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = onSaveConfig,
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(if (isSaving) "Saving" else "Save")
                }
                OutlinedButton(
                    onClick = onResetConfig,
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Reset")
                }
            }
            if (hasUnsavedConfig) {
                Text("Unsaved config changes.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            statusMessage?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            errorMessage?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.error)
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
    title: String,
    fileKinds: List<RuntimeFileKind>,
    state: RuntimeFilesUiState,
    actionsEnabled: Boolean,
    onRuntimeFileSelected: (RuntimeFileKind) -> Unit,
    onRuntimeFileTextChanged: (RuntimeFileKind, String) -> Unit,
    onSaveRuntimeFile: (RuntimeFileKind) -> Unit,
    onResetRuntimeFile: (RuntimeFileKind) -> Unit,
    onImportRuntimeFile: (RuntimeFileKind) -> Unit,
    onExportRuntimeFile: (RuntimeFileKind) -> Unit,
    onShareRuntimeFile: (RuntimeFileKind) -> Unit,
    onRunTestScan: (RuntimeFileKind) -> Unit,
) {
    val selectedFile = if (state.selectedFile in fileKinds) {
        state.selectedFile
    } else {
        fileKinds.first()
    }
    val selectedText = state.textFor(selectedFile)
    val selectedListValidation = state.validationFor(selectedFile)
    val selectedFileCanRunTestScan = selectedFile != RuntimeFileKind.Config
    val fileActionsEnabled = actionsEnabled && !state.isLoading && !state.isSaving

    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(title, fontWeight = FontWeight.SemiBold)
            if (state.runtimeDir.isNotBlank()) {
                Text(
                    text = state.runtimeDir,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (fileKinds.size > 1) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    fileKinds.forEach { kind ->
                        val label = if (kind in state.dirtyFiles) {
                            "${kind.title} *"
                        } else {
                            kind.title
                        }
                        if (kind == selectedFile) {
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
            } else {
                fileKinds.firstOrNull()?.let { kind ->
                    val label = if (kind in state.dirtyFiles) {
                        "${kind.title} *"
                    } else {
                        kind.title
                    }
                    Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            selectedListValidation?.let { validation ->
                RuntimeListValidationSummary(
                    kind = selectedFile,
                    validation = validation,
                )
            }
            if (state.isLoading) {
                Text("Loading runtime files.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                OutlinedTextField(
                    value = selectedText,
                    onValueChange = { onRuntimeFileTextChanged(selectedFile, it) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 220.dp, max = 360.dp),
                    enabled = fileActionsEnabled,
                    isError = selectedListValidation?.issues?.isNotEmpty() == true,
                    label = { Text(selectedFile.fileName) },
                    textStyle = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                    ),
                    minLines = 10,
                    maxLines = 18,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { onSaveRuntimeFile(selectedFile) },
                    enabled = fileActionsEnabled,
                ) {
                    Text(if (state.isSaving) "Saving" else "Save")
                }
                OutlinedButton(
                    onClick = { onResetRuntimeFile(selectedFile) },
                    enabled = fileActionsEnabled,
                ) {
                    Text("Reset to defaults")
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { onImportRuntimeFile(selectedFile) },
                    enabled = fileActionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Import")
                }
                OutlinedButton(
                    onClick = { onExportRuntimeFile(selectedFile) },
                    enabled = fileActionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Export")
                }
                OutlinedButton(
                    onClick = { onShareRuntimeFile(selectedFile) },
                    enabled = fileActionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Share")
                }
            }
            if (selectedFileCanRunTestScan) {
                Button(
                    onClick = { onRunTestScan(selectedFile) },
                    enabled = fileActionsEnabled &&
                        state.configEditor.canStart &&
                        selectedListValidation?.isValid == true,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        when (selectedFile) {
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
        DetailRow("Root", state.rootStatus.label)
        DetailRow("Mode", state.mode)
        DetailRow("Bypass", state.bypassMethod)
        DetailRow("Listener", state.listener)
        DetailRow("Active target", state.activeTarget)
        DetailRow("Active score", state.activeTargetScore?.toString() ?: "Unknown")
        DetailRow("Connections", state.connectionCount.toString())
        DetailRow("Relay bytes", state.relayBytes.toString())
        DetailRow("Last exit code", state.lastExitCode?.toString() ?: "None")
    }
}

@Composable
private fun DiagnosticsPanel(
    serviceState: ZeroDpiServiceState,
    runtimeFilesState: RuntimeFilesUiState,
    diagnosticsState: DiagnosticsUiState,
    onRefreshDiagnostics: () -> Unit,
    onExportSupportBundle: (Boolean) -> Unit,
) {
    var includePrivateLists by remember { mutableStateOf(false) }
    val diagnostics = diagnosticsState.diagnostics
    val configValidation = if (runtimeFilesState.configEditor.canStart) {
        "Valid"
    } else {
        "${runtimeFilesState.configEditor.issues.size} error(s)"
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Diagnostics", fontWeight = FontWeight.SemiBold)
            DetailRow("App version", diagnostics.appVersion)
            DetailRow("ZeroDPI version", diagnostics.zeroDpiVersion)
            DetailRow("ABI", diagnostics.abi)
            DetailRow("Android", diagnostics.androidVersion)
            DetailRow("Root status", serviceState.rootStatus.label)
            DetailRow("Firewall backend", diagnostics.firewallBackendAvailability)
            DetailRow("Config validation", configValidation)
            DetailRow("Last exit code", serviceState.lastExitCode?.toString() ?: "None")

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = onRefreshDiagnostics,
                    enabled = !diagnosticsState.isRefreshing,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(if (diagnosticsState.isRefreshing) "Refreshing" else "Refresh")
                }
                Button(
                    onClick = { onExportSupportBundle(includePrivateLists) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Export bundle")
                }
            }

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
                    Text("Include private lists", fontWeight = FontWeight.Medium)
                    Text(
                        text = "Off by default so SNI/IP production lists are not exported silently.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Switch(
                    checked = includePrivateLists,
                    onCheckedChange = { includePrivateLists = it },
                )
            }
            diagnosticsState.statusMessage?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            diagnosticsState.errorMessage?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.42f),
        )
        Text(
            text = value,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(0.58f),
        )
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

private fun canChangeProfiles(status: RuntimeStatus): Boolean =
    when (status) {
        RuntimeStatus.Starting,
        RuntimeStatus.Scanning,
        RuntimeStatus.Running,
        RuntimeStatus.Stopping,
        -> false

        RuntimeStatus.Stopped,
        RuntimeStatus.Failed,
        -> true
    }

private fun uniqueProfileName(
    baseName: String,
    profiles: List<ZeroDpiProfile>,
): String {
    val existingNames = profiles.mapTo(mutableSetOf()) { it.name.trim().lowercase(Locale.US) }
    val normalizedBase = baseName
        .trim()
        .ifBlank { "Profile" }
        .take(ZeroDpiProfile.MAX_NAME_LENGTH)
    if (normalizedBase.lowercase(Locale.US) !in existingNames) {
        return normalizedBase
    }
    var index = 2
    while (true) {
        val suffix = " $index"
        val candidate = normalizedBase
            .take(ZeroDpiProfile.MAX_NAME_LENGTH - suffix.length)
            .trimEnd() + suffix
        if (candidate.trim().lowercase(Locale.US) !in existingNames) {
            return candidate
        }
        index += 1
    }
}

private fun formatEpochMs(epochMs: Long?): String {
    if (epochMs == null) {
        return "Never"
    }
    return SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(epochMs))
}

private const val MAX_VISIBLE_VALIDATION_ERRORS = 6
private const val MAX_VISIBLE_LIST_ERRORS = 6
