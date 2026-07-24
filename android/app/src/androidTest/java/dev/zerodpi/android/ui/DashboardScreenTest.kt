package dev.zerodpi.android.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiServiceState
import dev.zerodpi.android.ui.theme.ZeroDpiTheme
import org.junit.Rule
import org.junit.Assert.assertEquals
import org.junit.Test

@Suppress("DEPRECATION")
class DashboardScreenTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun bottomNavigationOpensEveryPrimaryDestination() {
        composeRule.setContent { TestDashboard() }

        composeRule.onNodeWithTag("screen_home").assertIsDisplayed()
        composeRule.onNodeWithTag("nav_profiles").performClick()
        composeRule.onNodeWithTag("screen_profiles").assertIsDisplayed()
        composeRule.onNodeWithTag("nav_configure").performClick()
        composeRule.onNodeWithTag("screen_configure").assertIsDisplayed()
        composeRule.onNodeWithTag("nav_logs").performClick()
        composeRule.onNodeWithTag("screen_logs").assertIsDisplayed()
    }

    @Test
    fun primaryDestinationsDoNotShowARepeatedTopBar() {
        composeRule.setContent { TestDashboard() }

        composeRule.onNodeWithTag("contextual_top_bar").assertDoesNotExist()
        listOf("profiles", "configure", "logs", "home").forEach { destination ->
            composeRule.onNodeWithTag("nav_$destination").performClick()
            composeRule.onNodeWithTag("contextual_top_bar").assertDoesNotExist()
        }
    }

    @Test
    fun runningRuntimeShowsStopAsPrimaryAction() {
        composeRule.setContent {
            TestDashboard(
                serviceState = ZeroDpiServiceState(status = RuntimeStatus.Running),
            )
        }

        composeRule.onNodeWithText("Stop ZeroDPI").assertIsDisplayed()
        composeRule.onNodeWithTag("runtime_primary_action").assertIsDisplayed()
    }

    @Test
    fun homeShowsSelectedTargetScore() {
        composeRule.setContent {
            TestDashboard(
                serviceState = ZeroDpiServiceState(activeTargetScore = 95),
            )
        }

        composeRule.onNodeWithText("Target score").assertIsDisplayed()
        composeRule.onNodeWithText("95").assertIsDisplayed()
        composeRule.onNodeWithText("Next scan").assertIsDisplayed()
    }

    @Test
    fun logsDestinationDisplaysRuntimeOutput() {
        composeRule.setContent {
            TestDashboard(
                serviceState = ZeroDpiServiceState(
                    recentLogs = listOf("first log", "latest log"),
                ),
            )
        }

        composeRule.onNodeWithTag("nav_logs").performClick()
        composeRule.onNodeWithText("first log").assertIsDisplayed()
        composeRule.onNodeWithText("latest log").assertIsDisplayed()
    }

    @Test
    fun logsCanSearchFilterPauseAndConfirmClear() {
        var clearCalls = 0
        composeRule.setContent {
            TestDashboard(
                serviceState = ZeroDpiServiceState(
                    status = RuntimeStatus.Running,
                    recentLogs = listOf(
                        "relay connected",
                        "WARNING: DNS retry",
                        "fatal runner error",
                    ),
                ),
                onClearLogs = { clearCalls += 1 },
            )
        }

        composeRule.onNodeWithTag("nav_logs").performClick()
        composeRule.onNodeWithTag("logs_filter_error").performClick()
        composeRule.onNodeWithText("fatal runner error").assertIsDisplayed()
        composeRule.onNodeWithText("relay connected").assertDoesNotExist()

        composeRule.onNodeWithTag("logs_search").performTextInput("missing")
        composeRule.onNodeWithText("No log entries match the current search and level filter.")
            .assertIsDisplayed()

        composeRule.onNodeWithTag("logs_auto_scroll").performClick()
        composeRule.onNodeWithText("Resume auto-scroll").assertIsDisplayed()

        composeRule.onNodeWithTag("logs_clear").performClick()
        composeRule.onNodeWithText("Delete all logs?").assertIsDisplayed()
        composeRule.onNodeWithTag("logs_clear_confirm").performClick()
        composeRule.runOnIdle { assertEquals(1, clearCalls) }
    }

    @Test
    fun configureSwitchesBetweenBasicAndAdvancedSections() {
        composeRule.setContent { TestDashboard() }
        composeRule.onNodeWithTag("nav_configure").performClick()

        composeRule.onNodeWithTag("config_section_ProxyListener").assertIsDisplayed()
        composeRule.onNodeWithTag("config_section_BypassEngine").assertIsDisplayed()
        composeRule.onNodeWithTag("config_advanced").performClick()
        composeRule.onNodeWithTag("config_section_ScanBehavior").assertIsDisplayed()
    }

    @Test
    fun invalidConfigurationOffersDirectRouteToConfigure() {
        composeRule.setContent { TestDashboard() }

        composeRule.onNodeWithText("Review configuration").assertIsDisplayed()
        composeRule.onNodeWithText("Review configuration").performClick()
        composeRule.onNodeWithTag("screen_configure").assertIsDisplayed()
    }

    @Test
    fun candidateListCardOpensDedicatedEditor() {
        composeRule.setContent { TestDashboard() }
        composeRule.onNodeWithTag("nav_configure").performClick()

        composeRule.onNodeWithText("SNI list").assertIsDisplayed()
        composeRule.onAllNodesWithText("Edit")[0].performClick()
        composeRule.onNodeWithTag("screen_list_snilist").assertIsDisplayed()
        composeRule.onNodeWithTag("list_editor").assertIsDisplayed()
        composeRule.onNodeWithTag("contextual_top_bar").assertIsDisplayed()
        composeRule.onNodeWithTag("nav_configure").assertDoesNotExist()
    }
}

@androidx.compose.runtime.Composable
private fun TestDashboard(
    serviceState: ZeroDpiServiceState = ZeroDpiServiceState(),
    runtimeFilesState: RuntimeFilesUiState = RuntimeFilesUiState(isLoading = false),
    profileState: ProfileUiState = ProfileUiState(isProfileLoading = false),
    diagnosticsState: DiagnosticsUiState = DiagnosticsUiState(),
    onClearLogs: () -> Unit = {},
) {
    ZeroDpiTheme {
        DashboardScreen(
            state = serviceState,
            runtimeFilesState = runtimeFilesState,
            profileState = profileState,
            diagnosticsState = diagnosticsState,
            onStart = {},
            onStop = {},
            onForceStop = {},
            onCreateProfile = {},
            onDuplicateActiveProfile = {},
            onRenameProfile = { _, _ -> },
            onDeleteProfile = {},
            onSelectProfile = {},
            onProfileRemoteConfigUrlChanged = {},
            onProfileRemoteSniListUrlChanged = {},
            onProfileRemoteIpListUrlChanged = {},
            onProfileAutoUpdateChanged = {},
            onProfileAutoUpdateIntervalChanged = {},
            onRunManualProfileUpdate = {},
            onRuntimeFileSelected = {},
            onRuntimeFileTextChanged = { _, _ -> },
            onConfigFieldChanged = { _, _ -> },
            onResetConfig = {},
            onResetRuntimeFile = {},
            onImportRuntimeFile = {},
            onExportRuntimeFile = {},
            onShareRuntimeFile = {},
            onRunTestScan = {},
            onRunRootDiagnostics = {},
            onRefreshDiagnostics = {},
            onExportSupportBundle = {},
            onClearLogs = onClearLogs,
        )
    }
}
