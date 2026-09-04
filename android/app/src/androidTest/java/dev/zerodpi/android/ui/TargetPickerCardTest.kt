package dev.zerodpi.android.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import dev.zerodpi.android.service.PickOrigin
import dev.zerodpi.android.service.ScanProgressInfo
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.TargetPin
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class TargetPickerCardTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val sniPin = TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L)

    @Test
    fun hiddenPhaseRendersNothing() {
        composeRule.setContent {
            TargetPickerCard(state = TargetPickUiState())
        }
        composeRule.onNodeWithTag("target_pick_card").assertDoesNotExist()
    }

    @Test
    fun idleWithoutPinOffersScanAndChoose() {
        var requested = false
        composeRule.setContent {
            TargetPickerCard(
                state = TargetPickUiState(phase = TargetPickPhase.Idle, mode = "sni_spoof"),
                onRequestPick = { requested = true },
            )
        }
        composeRule.onNodeWithTag("target_pick_scan").performClick()
        assertTrue(requested)
    }

    @Test
    fun idleWithPinShowsTargetAndClearAction() {
        composeRule.setContent {
            TargetPickerCard(
                state = TargetPickUiState(phase = TargetPickPhase.Idle, mode = "sni_spoof", pin = sniPin),
            )
        }
        composeRule.onNodeWithText("cloudflare.com (1.1.1.1)").assertIsDisplayed()
        composeRule.onNodeWithTag("target_pick_clear").assertIsDisplayed()
    }

    @Test
    fun choosingRendersRankedRowsAndSelectsEnabledRow() {
        var chosen: TargetPickEntryModel? = null
        composeRule.setContent {
            TargetPickerCard(
                state = TargetPickUiState(
                    phase = TargetPickPhase.Choosing,
                    mode = "sni_spoof",
                    origin = PickOrigin.Standalone,
                    entries = listOf(
                        TargetPickEntryModel("cloudflare.com", "1.1.1.1", 95, 35L),
                        TargetPickEntryModel("unreachable.example", "10.0.0.1", 0, null),
                    ),
                ),
                onChoose = { chosen = it },
            )
        }
        composeRule.onNodeWithTag("target_pick_row_0").assertIsDisplayed()
        composeRule.onNodeWithText("failed").assertIsDisplayed()
        composeRule.onNodeWithTag("target_pick_row_0").performClick()
        assertTrue(chosen?.sni == "cloudflare.com")
    }

    @Test
    fun scanningShowsProgressAndCancel() {
        composeRule.setContent {
            TargetPickerCard(
                state = TargetPickUiState(
                    phase = TargetPickPhase.Scanning,
                    mode = "sni_spoof",
                    progress = ScanProgressInfo(scan = "sni", completed = 2, total = 5),
                ),
            )
        }
        composeRule.onNodeWithTag("target_pick_progress").assertIsDisplayed()
        composeRule.onNodeWithTag("target_pick_cancel").assertIsDisplayed()
    }

    @Test
    fun failedShowsMessageAndRetryAction() {
        var requested = false
        composeRule.setContent {
            TargetPickerCard(
                state = TargetPickUiState(phase = TargetPickPhase.Failed("boom"), mode = "sni_spoof"),
                onRequestPick = { requested = true },
            )
        }
        composeRule.onNodeWithTag("target_pick_error").assertIsDisplayed()
        composeRule.onNodeWithTag("target_pick_scan").performClick()
        assertTrue(requested)
    }
}
