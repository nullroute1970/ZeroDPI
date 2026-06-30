package dev.zerodpi.android.profile

import dev.zerodpi.android.config.ConfigValidationIssue
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.list.RuntimeListIssue
import dev.zerodpi.android.list.RuntimeListValidation
import dev.zerodpi.android.list.RuntimeListValidator
import dev.zerodpi.android.storage.RuntimeFileKind

data class ProfileUpdateFileContents(
    val configText: String,
    val sniListText: String,
    val ipListText: String,
)

data class ProfileUpdateResult(
    val index: ProfileIndex,
    val successful: Boolean,
    val message: String,
)

class ProfileUpdateManager(
    private val profileRepository: ProfileRepository,
    private val remoteClient: ProfileRemoteClient = HttpUrlConnectionProfileRemoteClient(),
    private val beforeApply: suspend () -> Unit = {},
) {
    suspend fun updateProfile(
        profileId: String,
        mode: ProfileUpdateMode,
        remote: ProfileRemoteSettings? = null,
    ): ProfileUpdateResult {
        val profile = profileRepository.loadIndex().profiles.firstOrNull { it.id == profileId }
            ?: throw IllegalArgumentException("Unknown profile id: $profileId")
        val remoteSettings = remote ?: profile.remote

        val remoteValidation = remoteSettings.validateForUpdate()
        if (!remoteValidation.isValid) {
            return recordFailure(
                profileId = profileId,
                mode = mode,
                message = remoteValidation.errors.joinToString("; ") { it.message }
                    .ifBlank { "Configure all three valid remote URLs before updating." },
                remote = remoteSettings.takeIf { it.validate().isValid },
            )
        }

        val downloadResult = runCatching {
            remoteClient.downloadAll(remoteSettings)
        }
        val downloads = downloadResult.getOrElse { error ->
            return recordFailure(
                profileId = profileId,
                mode = mode,
                message = error.message ?: "Failed to download remote profile files.",
                remote = remoteSettings,
            )
        }

        if (!downloads.isSuccess) {
            return recordFailure(
                profileId = profileId,
                mode = mode,
                message = downloads.failureMessage(),
                remote = remoteSettings,
            )
        }

        val files = ProfileUpdateFileContents(
            configText = downloads.config.contentText.orEmpty(),
            sniListText = downloads.sniList.contentText.orEmpty(),
            ipListText = downloads.ipList.contentText.orEmpty(),
        )
        validateFiles(files)?.let { validationMessage ->
            return recordFailure(
                profileId = profileId,
                mode = mode,
                message = validationMessage,
                remote = remoteSettings,
            )
        }

        val successMessage = "Updated profile from remote."
        val applyResult = runCatching {
            beforeApply()
            profileRepository.applyRemoteUpdate(
                profileId = profileId,
                remote = remoteSettings,
                files = files,
                mode = mode,
                message = successMessage,
            )
        }
        return if (applyResult.isSuccess) {
            ProfileUpdateResult(
                index = applyResult.getOrThrow(),
                successful = true,
                message = successMessage,
            )
        } else {
            val error = applyResult.exceptionOrNull()
            recordFailure(
                profileId = profileId,
                mode = mode,
                message = error?.message ?: "Failed to apply remote profile update.",
                remote = remoteSettings,
            )
        }
    }

    private suspend fun recordFailure(
        profileId: String,
        mode: ProfileUpdateMode,
        message: String,
        remote: ProfileRemoteSettings?,
    ): ProfileUpdateResult {
        val index = profileRepository.recordRemoteUpdateFailure(
            profileId = profileId,
            mode = mode,
            message = message,
            remote = remote,
        )
        return ProfileUpdateResult(index = index, successful = false, message = message)
    }

    private fun validateFiles(files: ProfileUpdateFileContents): String? {
        val configAnalysis = ZeroDpiConfigToml.analyze(files.configText)
        if (configAnalysis.issues.isNotEmpty()) {
            return "config.toml validation failed: ${configAnalysis.issues.issueMessage()}."
        }

        val mode = configAnalysis.valueFor("MODE")
        val sniValidation = RuntimeListValidator.validate(
            kind = RuntimeFileKind.SniList,
            text = files.sniListText,
            mode = mode,
        )
        if (!sniValidation.isValid) {
            return "sni_list.txt validation failed: ${sniValidation.issueMessage()}."
        }

        val ipValidation = RuntimeListValidator.validate(
            kind = RuntimeFileKind.IpList,
            text = files.ipListText,
            mode = mode,
        )
        if (!ipValidation.isValid) {
            return "ip_list.txt validation failed: ${ipValidation.issueMessage()}."
        }

        return null
    }

    private fun ProfileRemoteDownloadSet.failureMessage(): String {
        val failures = results.filterNot { it.isSuccess }
        return failures.joinToString("; ") { result ->
            "${result.file.fileName}: ${result.errorMessage ?: "download did not return content"}"
        }.ifBlank {
            "Failed to download remote profile files."
        }
    }

    private fun List<ConfigValidationIssue>.issueMessage(): String =
        take(MAX_REPORTED_ISSUES).joinToString("; ") { issue ->
            issue.fieldName?.let { field -> "$field: ${issue.message}" } ?: issue.message
        }

    private fun RuntimeListValidation.issueMessage(): String =
        issues.take(MAX_REPORTED_ISSUES).joinToString("; ") { issue ->
            issue.describe()
        }

    private fun RuntimeListIssue.describe(): String =
        "line $lineNumber: $message"

    private companion object {
        private const val MAX_REPORTED_ISSUES = 3
    }
}
