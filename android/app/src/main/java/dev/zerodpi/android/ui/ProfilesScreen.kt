package dev.zerodpi.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.service.RuntimeStatus
import java.text.DateFormat
import java.util.Date

@Composable
internal fun ProfilesScreen(
    serviceStatus: RuntimeStatus,
    profileState: ProfileUiState,
    runtimeFilesState: RuntimeFilesUiState,
    actionsEnabled: Boolean,
    onCreateProfile: (String) -> Unit,
    onDuplicateActiveProfile: (String) -> Unit,
    onRenameProfile: (String, String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onSelectProfile: (String) -> Unit,
    onConfigUrlChanged: (String) -> Unit,
    onSniListUrlChanged: (String) -> Unit,
    onIpListUrlChanged: (String) -> Unit,
    onAutoUpdateChanged: (Boolean) -> Unit,
    onIntervalHoursChanged: (Int) -> Unit,
    onRunManualUpdate: () -> Unit,
) {
    var dialog by rememberSaveable { mutableStateOf<ProfileDialog?>(null) }
    var showDeleteDialog by rememberSaveable { mutableStateOf(false) }
    val activeProfile = profileState.activeProfile

    Column(
        modifier = Modifier
            .fillMaxSize()
            .testTag("screen_profiles")
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.profiles_description),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (!canChangeProfiles(serviceStatus)) {
            InlineMessage(stringResource(R.string.profiles_stop_first))
        }
        if (profileState.isProfileSwitching) {
            InlineMessage(stringResource(R.string.profiles_switching))
        }

        profileState.profiles.forEach { profile ->
            val selected = profile.id == profileState.activeProfileId
            androidx.compose.material3.Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(
                        enabled = actionsEnabled && !selected,
                        onClick = { onSelectProfile(profile.id) },
                    )
                    .testTag("profile_${profile.id}"),
                shape = MaterialTheme.shapes.large,
                color = if (selected) {
                    MaterialTheme.colorScheme.primaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceContainer
                },
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(
                        selected = selected,
                        onClick = {
                            if (!selected) {
                                onSelectProfile(profile.id)
                            }
                        },
                        enabled = actionsEnabled,
                    )
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .padding(horizontal = 8.dp),
                    ) {
                        Text(
                            text = profile.name,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            text = profile.id,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    if (selected) {
                        Text(
                            text = stringResource(R.string.profiles_active),
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
            }
        }

        SectionCard(title = stringResource(R.string.profiles_title)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = {
                        dialog = ProfileDialog.Create(
                            uniqueProfileName("New profile", profileState.profiles),
                        )
                    },
                    enabled = actionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.Add, contentDescription = null)
                    Text(
                        stringResource(R.string.action_create),
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
                OutlinedButton(
                    onClick = {
                        dialog = ProfileDialog.Duplicate(
                            uniqueProfileName(
                                "${profileState.activeProfileName} copy",
                                profileState.profiles,
                            ),
                        )
                    },
                    enabled = actionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null)
                    Text(
                        stringResource(R.string.action_duplicate),
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = {
                        activeProfile?.let { dialog = ProfileDialog.Rename(it.id, it.name) }
                    },
                    enabled = actionsEnabled && activeProfile != null,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.Edit, contentDescription = null)
                    Text(
                        stringResource(R.string.action_rename),
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
                OutlinedButton(
                    onClick = { showDeleteDialog = true },
                    enabled = actionsEnabled && profileState.profiles.size > 1,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.Delete, contentDescription = null)
                    Text(
                        stringResource(R.string.action_delete),
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
            }
            if (profileState.profiles.size <= 1) {
                InlineMessage(stringResource(R.string.profiles_last_delete))
            }
        }

        RemoteUpdateSection(
            profileState = profileState,
            runtimeFilesState = runtimeFilesState,
            actionsEnabled = actionsEnabled,
            onConfigUrlChanged = onConfigUrlChanged,
            onSniListUrlChanged = onSniListUrlChanged,
            onIpListUrlChanged = onIpListUrlChanged,
            onAutoUpdateChanged = onAutoUpdateChanged,
            onIntervalHoursChanged = onIntervalHoursChanged,
            onRunManualUpdate = onRunManualUpdate,
        )

        profileState.statusMessage?.let { InlineMessage(it) }
        profileState.lastProfileError?.let { InlineMessage(it, error = true) }
    }

    dialog?.let { profileDialog ->
        ProfileNameDialog(
            title = when (profileDialog) {
                is ProfileDialog.Create -> stringResource(R.string.action_create)
                is ProfileDialog.Duplicate -> stringResource(R.string.action_duplicate)
                is ProfileDialog.Rename -> stringResource(R.string.action_rename)
            },
            initialName = profileDialog.initialName,
            onDismiss = { dialog = null },
            onConfirm = { name ->
                when (profileDialog) {
                    is ProfileDialog.Create -> onCreateProfile(name)
                    is ProfileDialog.Duplicate -> onDuplicateActiveProfile(name)
                    is ProfileDialog.Rename -> onRenameProfile(profileDialog.profileId, name)
                }
                dialog = null
            },
        )
    }

    if (showDeleteDialog && activeProfile != null) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text(stringResource(R.string.profiles_delete_title)) },
            text = {
                Text(stringResource(R.string.profiles_delete_message, activeProfile.name))
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDeleteDialog = false
                        onDeleteProfile(activeProfile.id)
                    },
                ) {
                    Text(stringResource(R.string.action_delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun RemoteUpdateSection(
    profileState: ProfileUiState,
    runtimeFilesState: RuntimeFilesUiState,
    actionsEnabled: Boolean,
    onConfigUrlChanged: (String) -> Unit,
    onSniListUrlChanged: (String) -> Unit,
    onIpListUrlChanged: (String) -> Unit,
    onAutoUpdateChanged: (Boolean) -> Unit,
    onIntervalHoursChanged: (Int) -> Unit,
    onRunManualUpdate: () -> Unit,
) {
    val remote = profileState.profileRemoteSettings
    val validation = remote.validate()
    val updateValidation = remote.validateForUpdate()
    var intervalText by remember(remote.autoUpdateIntervalHours) {
        mutableStateOf(remote.autoUpdateIntervalHours.toString())
    }
    var showConfirm by rememberSaveable { mutableStateOf(false) }

    ExpandableSectionCard(
        title = stringResource(R.string.profiles_remote_update),
        initiallyExpanded = remote.hasAnyRemoteUrl || remote.autoUpdateEnabled,
        testTag = "remote_update_section",
    ) {
        InlineMessage(stringResource(R.string.profiles_remote_description))
        RemoteUrlField(
            label = stringResource(R.string.profiles_config_url),
            value = remote.configUrl,
            enabled = actionsEnabled,
            onValueChange = onConfigUrlChanged,
        )
        RemoteUrlField(
            label = stringResource(R.string.profiles_sni_url),
            value = remote.sniListUrl,
            enabled = actionsEnabled,
            onValueChange = onSniListUrlChanged,
        )
        RemoteUrlField(
            label = stringResource(R.string.profiles_ip_url),
            value = remote.ipListUrl,
            enabled = actionsEnabled,
            onValueChange = onIpListUrlChanged,
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.profiles_auto_update),
                    fontWeight = FontWeight.Medium,
                )
                InlineMessage(stringResource(R.string.profiles_remote_warning))
            }
            Switch(
                checked = remote.autoUpdateEnabled,
                onCheckedChange = onAutoUpdateChanged,
                enabled = actionsEnabled,
            )
        }
        OutlinedTextField(
            value = intervalText,
            onValueChange = { value ->
                intervalText = value
                value.toIntOrNull()?.let(onIntervalHoursChanged)
            },
            enabled = actionsEnabled,
            singleLine = true,
            label = { Text(stringResource(R.string.profiles_update_interval)) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        validation.errors.forEach { InlineMessage(it.message, error = true) }
        validation.warnings.forEach { InlineMessage(it.message) }
        if (validation.isValid && !updateValidation.isValid) {
            InlineMessage(stringResource(R.string.profiles_urls_required))
        }
        Button(
            onClick = { showConfirm = true },
            enabled = actionsEnabled && updateValidation.isValid,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("profile_update_now"),
        ) {
            Icon(Icons.Default.CloudDownload, contentDescription = null)
            Text(
                text = if (profileState.isRemoteUpdating) {
                    stringResource(R.string.profiles_updating)
                } else {
                    stringResource(R.string.action_update)
                },
                modifier = Modifier.padding(start = 8.dp),
            )
        }
        if (profileState.isRemoteUpdating) {
            InlineMessage(stringResource(R.string.profiles_updating))
        }
        DetailRow("Last attempt", formatEpochMs(remote.lastUpdateAttemptEpochMs))
        DetailRow("Last success", formatEpochMs(remote.lastSuccessfulUpdateEpochMs))
        remote.lastUpdateStatus?.let { status ->
            InlineMessage(status.message, error = !status.successful)
        }
        if (runtimeFilesState.dirtyFiles.isNotEmpty()) {
            InlineMessage(stringResource(R.string.configure_saving))
        }
    }

    if (showConfirm) {
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text(stringResource(R.string.profiles_remote_update)) },
            text = { Text(stringResource(R.string.profiles_remote_warning)) },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirm = false
                        onRunManualUpdate()
                    },
                ) {
                    Text(stringResource(R.string.action_update))
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirm = false }) {
                    Text(stringResource(R.string.action_cancel))
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
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
    )
}

@Composable
private fun ProfileNameDialog(
    title: String,
    initialName: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var name by rememberSaveable(initialName) { mutableStateOf(initialName) }
    val trimmedName = name.trim()
    val validation = ZeroDpiProfile.validateName(trimmedName)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.profiles_title)) },
                    isError = !validation.isValid,
                )
                validation.errors.forEach { InlineMessage(it.message, error = true) }
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(trimmedName) },
                enabled = validation.isValid,
            ) {
                Text(title)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}

private sealed interface ProfileDialog {
    val initialName: String

    data class Create(override val initialName: String) : ProfileDialog
    data class Duplicate(override val initialName: String) : ProfileDialog
    data class Rename(
        val profileId: String,
        override val initialName: String,
    ) : ProfileDialog
}

private fun uniqueProfileName(
    base: String,
    profiles: List<ZeroDpiProfile>,
): String {
    val existing = profiles.map { it.name.lowercase() }.toSet()
    if (base.lowercase() !in existing) {
        return base
    }
    var suffix = 2
    while ("$base $suffix".lowercase() in existing) {
        suffix += 1
    }
    return "$base $suffix"
}

private fun formatEpochMs(epochMs: Long?): String =
    epochMs?.let { DateFormat.getDateTimeInstance().format(Date(it)) } ?: "Never"
