package dev.zerodpi.android.profile

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.net.URI
import java.util.Locale

private const val PROFILE_INDEX_SCHEMA_VERSION = 1

@Serializable
data class ZeroDpiProfile(
    val id: String,
    val name: String,
    val createdAtEpochMs: Long,
    val updatedAtEpochMs: Long,
    val remote: ProfileRemoteSettings = ProfileRemoteSettings(),
) {
    init {
        validateId(id).requireValid("Profile id")
        validateName(name).requireValid("Profile name")
        require(createdAtEpochMs >= 0) { "Profile created timestamp must be non-negative." }
        require(updatedAtEpochMs >= 0) { "Profile updated timestamp must be non-negative." }
        require(updatedAtEpochMs >= createdAtEpochMs) {
            "Profile updated timestamp cannot be older than created timestamp."
        }
    }

    fun validate(): ProfileValidationResult {
        val errors = mutableListOf<ProfileValidationIssue>()
        val warnings = mutableListOf<ProfileValidationIssue>()

        errors += validateId(id).errors
        errors += validateName(name).errors
        if (createdAtEpochMs < 0) {
            errors += ProfileValidationIssue("createdAtEpochMs", "Created timestamp must be non-negative.")
        }
        if (updatedAtEpochMs < 0) {
            errors += ProfileValidationIssue("updatedAtEpochMs", "Updated timestamp must be non-negative.")
        }
        if (createdAtEpochMs >= 0 && updatedAtEpochMs >= 0 && updatedAtEpochMs < createdAtEpochMs) {
            errors += ProfileValidationIssue(
                "updatedAtEpochMs",
                "Updated timestamp cannot be older than created timestamp.",
            )
        }

        val remoteResult = remote.validate().prefixed("remote")
        errors += remoteResult.errors
        warnings += remoteResult.warnings

        return ProfileValidationResult(errors = errors, warnings = warnings)
    }

    companion object {
        const val DEFAULT_PROFILE_ID = "default"
        const val DEFAULT_PROFILE_NAME = "Default"
        const val MAX_ID_LENGTH = 64
        const val MAX_NAME_LENGTH = 64

        private val idPattern = Regex("""[A-Za-z0-9][A-Za-z0-9_-]{0,63}""")

        fun default(createdAtEpochMs: Long = 0L): ZeroDpiProfile =
            ZeroDpiProfile(
                id = DEFAULT_PROFILE_ID,
                name = DEFAULT_PROFILE_NAME,
                createdAtEpochMs = createdAtEpochMs,
                updatedAtEpochMs = createdAtEpochMs,
            )

        fun validateId(id: String): ProfileValidationResult {
            val errors = mutableListOf<ProfileValidationIssue>()
            if (id.isBlank()) {
                errors += ProfileValidationIssue("id", "Profile id cannot be blank.")
            }
            if (id.length > MAX_ID_LENGTH) {
                errors += ProfileValidationIssue("id", "Profile id cannot exceed $MAX_ID_LENGTH characters.")
            }
            if (!idPattern.matches(id)) {
                errors += ProfileValidationIssue(
                    "id",
                    "Profile id may contain only letters, numbers, underscores, and dashes.",
                )
            }
            return ProfileValidationResult(errors = errors)
        }

        fun validateName(name: String): ProfileValidationResult {
            val errors = mutableListOf<ProfileValidationIssue>()
            val trimmed = name.trim()
            if (trimmed.isEmpty()) {
                errors += ProfileValidationIssue("name", "Profile name cannot be blank.")
            }
            if (trimmed.length > MAX_NAME_LENGTH) {
                errors += ProfileValidationIssue(
                    "name",
                    "Profile name cannot exceed $MAX_NAME_LENGTH characters.",
                )
            }
            if (name != trimmed) {
                errors += ProfileValidationIssue("name", "Profile name must be trimmed.")
            }
            return ProfileValidationResult(errors = errors)
        }

        internal fun duplicateKeyForName(name: String): String =
            name.trim().lowercase(Locale.US)
    }
}

@Serializable
data class ProfileRemoteSettings(
    val configUrl: String = "",
    val sniListUrl: String = "",
    val ipListUrl: String = "",
    val autoUpdateEnabled: Boolean = false,
    val autoUpdateIntervalHours: Int = 24,
    val lastUpdateAttemptEpochMs: Long? = null,
    val lastSuccessfulUpdateEpochMs: Long? = null,
    val lastUpdateStatus: ProfileUpdateStatus? = null,
) {
    val hasAnyRemoteUrl: Boolean
        get() = remoteUrls.any { it.isNotBlank() }

    val hasCompleteRemoteUrls: Boolean
        get() = remoteUrls.all { it.isNotBlank() }

    fun validate(requireConfigured: Boolean = false): ProfileValidationResult {
        val errors = mutableListOf<ProfileValidationIssue>()
        val warnings = mutableListOf<ProfileValidationIssue>()

        if (autoUpdateIntervalHours <= 0) {
            errors += ProfileValidationIssue(
                "autoUpdateIntervalHours",
                "Automatic update interval must be positive.",
            )
        }
        lastUpdateAttemptEpochMs?.let { timestamp ->
            if (timestamp < 0) {
                errors += ProfileValidationIssue(
                    "lastUpdateAttemptEpochMs",
                    "Last update attempt timestamp must be non-negative.",
                )
            }
        }
        lastSuccessfulUpdateEpochMs?.let { timestamp ->
            if (timestamp < 0) {
                errors += ProfileValidationIssue(
                    "lastSuccessfulUpdateEpochMs",
                    "Last successful update timestamp must be non-negative.",
                )
            }
        }

        val configuredCount = remoteUrls.count { it.isNotBlank() }
        if ((requireConfigured || autoUpdateEnabled || configuredCount > 0) && configuredCount != remoteUrls.size) {
            errors += ProfileValidationIssue(
                "remote",
                "Config, SNI list, and IP list URLs are all required for profile updates.",
            )
        }

        validateRemoteUrl("configUrl", configUrl, errors, warnings)
        validateRemoteUrl("sniListUrl", sniListUrl, errors, warnings)
        validateRemoteUrl("ipListUrl", ipListUrl, errors, warnings)

        return ProfileValidationResult(errors = errors, warnings = warnings)
    }

    fun validateForUpdate(): ProfileValidationResult =
        validate(requireConfigured = true)

    private val remoteUrls: List<String>
        get() = listOf(configUrl, sniListUrl, ipListUrl)

    private fun validateRemoteUrl(
        field: String,
        value: String,
        errors: MutableList<ProfileValidationIssue>,
        warnings: MutableList<ProfileValidationIssue>,
    ) {
        val trimmed = value.trim()
        if (trimmed.isBlank()) {
            return
        }
        if (value != trimmed) {
            errors += ProfileValidationIssue(field, "Remote URL must be trimmed.")
            return
        }

        val uri = runCatching { URI(trimmed) }.getOrNull()
        val scheme = uri?.scheme?.lowercase(Locale.US)
        if (uri == null || !uri.isAbsolute || uri.host.isNullOrBlank() || scheme !in allowedSchemes) {
            errors += ProfileValidationIssue(
                field,
                "Remote URL must be an absolute http or https URL.",
            )
            return
        }

        if (scheme == "http") {
            warnings += ProfileValidationIssue(field, "HTTP remote URLs are not encrypted.")
        }
    }

    private companion object {
        private val allowedSchemes = setOf("http", "https")
    }
}

@Serializable
data class ProfileUpdateStatus(
    val mode: ProfileUpdateMode,
    val successful: Boolean,
    val message: String = "",
    val completedAtEpochMs: Long,
) {
    init {
        require(completedAtEpochMs >= 0) { "Profile update completion timestamp must be non-negative." }
    }
}

@Serializable
enum class ProfileUpdateMode {
    @SerialName("manual")
    Manual,

    @SerialName("automatic")
    Automatic,
}

@Serializable
data class ProfileIndex(
    val schemaVersion: Int = PROFILE_INDEX_SCHEMA_VERSION,
    val activeProfileId: String = ZeroDpiProfile.DEFAULT_PROFILE_ID,
    val profiles: List<ZeroDpiProfile> = listOf(ZeroDpiProfile.default()),
) {
    fun validate(): ProfileValidationResult {
        val errors = mutableListOf<ProfileValidationIssue>()
        val warnings = mutableListOf<ProfileValidationIssue>()

        if (schemaVersion != SCHEMA_VERSION) {
            errors += ProfileValidationIssue(
                "schemaVersion",
                "Unsupported profile index schema version: $schemaVersion.",
            )
        }
        errors += ZeroDpiProfile.validateId(activeProfileId).prefixed("activeProfileId").errors
        if (profiles.isEmpty()) {
            errors += ProfileValidationIssue("profiles", "At least one profile is required.")
        }

        val idCounts = profiles.groupingBy { it.id }.eachCount()
        val duplicateIds = idCounts.filterValues { it > 1 }.keys
        if (duplicateIds.isNotEmpty()) {
            errors += ProfileValidationIssue("profiles", "Profile ids must be unique.")
        }

        val nameCounts = profiles.groupingBy { ZeroDpiProfile.duplicateKeyForName(it.name) }.eachCount()
        val duplicateNames = nameCounts.filterValues { it > 1 }.keys
        if (duplicateNames.isNotEmpty()) {
            errors += ProfileValidationIssue("profiles", "Profile names must be unique.")
        }

        if (profiles.none { it.id == activeProfileId }) {
            errors += ProfileValidationIssue("activeProfileId", "Active profile id must reference an existing profile.")
        }

        profiles.forEachIndexed { index, profile ->
            val profileResult = profile.validate().prefixed("profiles[$index]")
            errors += profileResult.errors
            warnings += profileResult.warnings
        }

        return ProfileValidationResult(errors = errors, warnings = warnings)
    }

    fun requireValid(): ProfileIndex =
        apply { validate().requireValid("Profile index") }

    fun toJson(): String {
        requireValid()
        return profileJson.encodeToString(this)
    }

    companion object {
        const val SCHEMA_VERSION = PROFILE_INDEX_SCHEMA_VERSION

        fun default(createdAtEpochMs: Long = 0L): ProfileIndex =
            ProfileIndex(
                schemaVersion = SCHEMA_VERSION,
                activeProfileId = ZeroDpiProfile.DEFAULT_PROFILE_ID,
                profiles = listOf(ZeroDpiProfile.default(createdAtEpochMs)),
            )

        fun fromJson(text: String): ProfileIndex =
            profileJson.decodeFromString<ProfileIndex>(text).requireValid()

        private val profileJson = Json {
            encodeDefaults = true
            ignoreUnknownKeys = true
            prettyPrint = true
        }
    }
}

data class ProfileValidationIssue(
    val field: String,
    val message: String,
)

data class ProfileValidationResult(
    val errors: List<ProfileValidationIssue> = emptyList(),
    val warnings: List<ProfileValidationIssue> = emptyList(),
) {
    val isValid: Boolean
        get() = errors.isEmpty()

    fun requireValid(subject: String) {
        require(isValid) {
            val details = errors.joinToString(separator = "; ") { issue ->
                "${issue.field}: ${issue.message}"
            }
            "$subject is invalid: $details"
        }
    }

    fun prefixed(prefix: String): ProfileValidationResult =
        ProfileValidationResult(
            errors = errors.map { it.prefixed(prefix) },
            warnings = warnings.map { it.prefixed(prefix) },
        )

    private fun ProfileValidationIssue.prefixed(prefix: String): ProfileValidationIssue =
        copy(field = if (field.isBlank()) prefix else "$prefix.$field")
}

object ProfilePaths {
    const val PROFILES_DIR_NAME = "profiles"
    const val INDEX_FILE_NAME = "index.json"

    fun indexFile(runtimeDir: File): File =
        File(File(runtimeDir, PROFILES_DIR_NAME), INDEX_FILE_NAME)

    fun profileDirectory(profilesDir: File, profileId: String): File {
        ZeroDpiProfile.validateId(profileId).requireValid("Profile id")
        return childFile(profilesDir, profileId)
    }

    fun childFile(profileDir: File, relativePath: String): File {
        require(relativePath.isNotBlank()) { "Profile relative path cannot be blank." }
        require(!File(relativePath).isAbsolute) { "Profile relative path must not be absolute." }

        val root = profileDir.canonicalFile
        val candidate = File(root, relativePath).canonicalFile
        require(candidate.isInside(root)) {
            "Profile path cannot escape profile directory: $relativePath"
        }
        return candidate
    }

    private fun File.isInside(root: File): Boolean {
        val rootPath = root.path
        val candidatePath = path
        return candidatePath == rootPath || candidatePath.startsWith(rootPath + File.separator)
    }
}
