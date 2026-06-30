package dev.zerodpi.android.profile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ProfileAutoUpdatePolicyTest {
    @Test
    fun dueProfilesIncludesEnabledProfilesWithoutPreviousAttempts() {
        val index = ProfileIndex(
            activeProfileId = "default",
            profiles = listOf(
                profile("default", remote = remote(autoUpdateEnabled = true)),
                profile("manual", remote = remote(autoUpdateEnabled = false)),
            ),
        )

        val due = ProfileAutoUpdatePolicy.dueProfiles(index, nowEpochMs = 10_000L)

        assertEquals(listOf("default"), due.map { it.id })
    }

    @Test
    fun dueProfilesWaitsUntilConfiguredIntervalHasElapsed() {
        val index = ProfileIndex(
            activeProfileId = "default",
            profiles = listOf(
                profile(
                    "default",
                    remote = remote(
                        autoUpdateEnabled = true,
                        intervalHours = 6,
                        lastAttemptEpochMs = 1_000L,
                    ),
                ),
                profile(
                    "due",
                    remote = remote(
                        autoUpdateEnabled = true,
                        intervalHours = 6,
                        lastAttemptEpochMs = 1_000L,
                    ),
                ),
            ),
        )

        val notYetDue = ProfileAutoUpdatePolicy.dueProfiles(
            index = index.copy(profiles = index.profiles.take(1)),
            nowEpochMs = 1_000L + 5L * 60L * 60L * 1000L,
        )
        val due = ProfileAutoUpdatePolicy.dueProfiles(
            index = index,
            nowEpochMs = 1_000L + 6L * 60L * 60L * 1000L,
        )

        assertEquals(emptyList<ZeroDpiProfile>(), notYetDue)
        assertEquals(listOf("default", "due"), due.map { it.id })
    }

    @Test
    fun repeatIntervalHoursUsesSmallestEnabledInterval() {
        val index = ProfileIndex(
            activeProfileId = "default",
            profiles = listOf(
                profile("default", remote = remote(autoUpdateEnabled = true, intervalHours = 24)),
                profile("fast", remote = remote(autoUpdateEnabled = true, intervalHours = 6)),
                profile("disabled", remote = remote(autoUpdateEnabled = false, intervalHours = 1)),
            ),
        )

        assertEquals(6L, ProfileAutoUpdatePolicy.repeatIntervalHours(index))
        assertNull(
            ProfileAutoUpdatePolicy.repeatIntervalHours(
                index.copy(profiles = listOf(profile("default", remote = remote(autoUpdateEnabled = false)))),
            ),
        )
    }

    private fun profile(
        id: String,
        remote: ProfileRemoteSettings,
    ): ZeroDpiProfile =
        ZeroDpiProfile(
            id = id,
            name = id.replaceFirstChar { it.uppercase() },
            createdAtEpochMs = 0L,
            updatedAtEpochMs = 0L,
            remote = remote,
        )

    private fun remote(
        autoUpdateEnabled: Boolean,
        intervalHours: Int = 24,
        lastAttemptEpochMs: Long? = null,
    ): ProfileRemoteSettings =
        ProfileRemoteSettings(
            configUrl = "https://example.com/config.toml",
            sniListUrl = "https://example.com/sni_list.txt",
            ipListUrl = "https://example.com/ip_list.txt",
            autoUpdateEnabled = autoUpdateEnabled,
            autoUpdateIntervalHours = intervalHours,
            lastUpdateAttemptEpochMs = lastAttemptEpochMs,
        )
}
