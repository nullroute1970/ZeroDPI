package dev.zerodpi.android.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import dev.zerodpi.android.service.RuntimeStatus
import dev.zerodpi.android.service.ZeroDpiServiceState
import dev.zerodpi.android.ui.theme.ZeroDpiTheme
import org.junit.Rule
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
        composeRule.onNodeWithTag("nav_support").performClick()
        composeRule.onNodeWithTag("screen_support").assertIsDisplayed()
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
    fun configureSwitchesBetweenBasicAndAdvancedSections() {
        composeRule.setContent { TestDashboard() }
        composeRule.onNodeWithTag("nav_configure").performClick()

        composeRule.onNodeWithTag("config_section_ProxyListener").assertIsDisplayed()
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
    }
}

@androidx.compose.runtime.Composable
private fun TestDashboard(
    serviceState: ZeroDpiServiceState = ZeroDpiServiceState(),
    runtimeFilesState: RuntimeFilesUiState = RuntimeFilesUiState(isLoading = false),
    profileState: ProfileUiState = ProfileUiState(isProfileLoading = false),
    diagnosticsState: DiagnosticsUiState = DiagnosticsUiState(),
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
        )
    }
}
