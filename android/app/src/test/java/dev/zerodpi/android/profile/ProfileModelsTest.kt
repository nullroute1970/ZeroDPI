package dev.zerodpi.android.profile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ProfileModelsTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun jsonRoundTripPreservesProfileMetadataAndStatus() {
        val index = ProfileIndex(
            activeProfileId = "default",
            profiles = listOf(
                ZeroDpiProfile(
                    id = "default",
                    name = "Default",
                    createdAtEpochMs = 10,
                    updatedAtEpochMs = 20,
                    remote = ProfileRemoteSettings(
                        configUrl = "https://example.com/zerodpi/config.toml",
                        sniListUrl = "https://example.com/zerodpi/sni_list.txt",
                        ipListUrl = "https://example.com/zerodpi/ip_list.txt",
                        autoUpdateEnabled = true,
                        autoUpdateIntervalHours = 24,
                        lastUpdateAttemptEpochMs = 30,
                        lastSuccessfulUpdateEpochMs = 31,
                        lastUpdateStatus = ProfileUpdateStatus(
                            mode = ProfileUpdateMode.Manual,
                            successful = true,
                            message = "Updated",
                            completedAtEpochMs = 31,
                        ),
                    ),
                ),
            ),
        )

        val json = index.toJson()
        val decoded = ProfileIndex.fromJson(json)

        assertEquals(index, decoded)
        assertTrue(json.contains("\"schemaVersion\": 1"))
        assertTrue(json.contains("\"mode\": \"manual\""))
    }

    @Test
    fun profileNameValidationRejectsBlankLongUntrimmedAndDuplicates() {
        assertFalse(ZeroDpiProfile.validateName("").isValid)
        assertFalse(ZeroDpiProfile.validateName("  Default").isValid)
        assertFalse(ZeroDpiProfile.validateName("a".repeat(65)).isValid)

        val index = ProfileIndex(
            activeProfileId = "first",
            profiles = listOf(
                profile(id = "first", name = "Default"),
                profile(id = "second", name = "default"),
            ),
        )
        val result = index.validate()

        assertFalse(result.isValid)
        assertTrue(result.errors.any { it.field == "profiles" && it.message.contains("names") })
    }

    @Test
    fun remoteValidationAllowsBlankUrlsButRequiresCompleteHttpUrlsForUpdate() {
        assertTrue(ProfileRemoteSettings().validate().isValid)
        assertFalse(ProfileRemoteSettings().validateForUpdate().isValid)

        val partial = ProfileRemoteSettings(
            configUrl = "https://example.com/config.toml",
        )
        assertFalse(partial.validate().isValid)

        val httpRemote = ProfileRemoteSettings(
            configUrl = "http://example.com/config.toml",
            sniListUrl = "https://example.com/sni_list.txt",
            ipListUrl = "https://example.com/ip_list.txt",
        )
        val httpResult = httpRemote.validateForUpdate()

        assertTrue(httpResult.isValid)
        assertEquals(listOf("configUrl"), httpResult.warnings.map { it.field })
    }

    @Test
    fun remoteValidationRejectsInvalidOrRelativeUrls() {
        val remote = ProfileRemoteSettings(
            configUrl = "file:///tmp/config.toml",
            sniListUrl = "example.com/sni_list.txt",
            ipListUrl = "https://example.com/ip_list.txt ",
        )
        val result = remote.validateForUpdate()

        assertFalse(result.isValid)
        assertEquals(
            setOf("configUrl", "sniListUrl", "ipListUrl"),
            result.errors.map { it.field }.toSet(),
        )
    }

    @Test
    fun profilePathsRejectEscapingIdsAndRelativePaths() {
        val profilesDir = temporaryFolder.newFolder("profiles")
        val profileDir = ProfilePaths.profileDirectory(profilesDir, "default")

        assertEquals(File(profilesDir, "default").canonicalFile, profileDir)
        assertEquals(
            File(profileDir, "scan_results/output.json").canonicalFile,
            ProfilePaths.childFile(profileDir, "scan_results/output.json"),
        )

        assertFailsWithIllegalArgument { ProfilePaths.profileDirectory(profilesDir, "../escape") }
        assertFailsWithIllegalArgument { ProfilePaths.profileDirectory(profilesDir, "nested/profile") }
        assertFailsWithIllegalArgument { ProfilePaths.childFile(profileDir, "../config.toml") }
        assertFailsWithIllegalArgument { ProfilePaths.childFile(profileDir, "/tmp/config.toml") }
    }

    @Test
    fun profileIndexJsonRejectsInvalidIdsAndMissingActiveProfile() {
        val invalidIdJson = """
            {
              "schemaVersion": 1,
              "activeProfileId": "../escape",
              "profiles": [
                {
                  "id": "../escape",
                  "name": "Default",
                  "createdAtEpochMs": 0,
                  "updatedAtEpochMs": 0,
                  "remote": {}
                }
              ]
            }
        """.trimIndent()
        val missingActiveIndex = ProfileIndex(
            activeProfileId = "missing",
            profiles = listOf(profile(id = "default")),
        )

        assertFailsWithIllegalArgument { ProfileIndex.fromJson(invalidIdJson) }
        assertFailsWithIllegalArgument { missingActiveIndex.toJson() }
    }

    private fun profile(
        id: String,
        name: String = "Profile $id",
    ): ZeroDpiProfile =
        ZeroDpiProfile(
            id = id,
            name = name,
            createdAtEpochMs = 0,
            updatedAtEpochMs = 0,
        )

    private inline fun assertFailsWithIllegalArgument(block: () -> Unit) {
        try {
            block()
            throw AssertionError("Expected IllegalArgumentException.")
        } catch (expected: IllegalArgumentException) {
            // Expected.
        }
    }
}
