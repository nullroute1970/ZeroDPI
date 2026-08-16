package dev.zerodpi.android.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import dev.zerodpi.android.methodscan.MethodScanEntryModel
import dev.zerodpi.android.methodscan.MethodScanReportModel
import dev.zerodpi.android.service.ScanProgressInfo
import org.junit.Rule
import org.junit.Test

class MethodScanCardTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val report = MethodScanReportModel(
        mode = "sni_method_scan",
        targetSni = "example.com",
        targetIp = "1.2.3.4",
        targetScore = 99,
        samplesPerMethod = 3,
        intervalMs = 1000,
        methods = listOf(
            MethodScanEntryModel(
                method = "wrong_seq", samplesTotal = 3, samplesOk = 3,
                successRate = 100.0, avgTtfbMs = 120.5, avgTlsMs = 40.0,
                httpStatus = 200, lastError = null,
            ),
            MethodScanEntryModel(
                method = "tls_frag", samplesTotal = 3, samplesOk = 0,
                successRate = 0.0, avgTtfbMs = null, avgTlsMs = null,
                httpStatus = null, lastError = "handshake timeout",
            ),
        ),
    )

    @Test
    fun showsProgressWhileRunning() {
        composeRule.setContent {
            MethodScanCard(
                state = MethodScanUiState(
                    phase = MethodScanPhase.Running,
                    mode = "sni_method_scan",
                    progress = ScanProgressInfo(scan = "proxy", phase = "method_test", completed = 2, total = 5),
                ),
            )
        }
        composeRule.onNodeWithTag("method_scan_progress").assertIsDisplayed()
    }

    @Test
    fun showsRankedRowsWhenCompleted() {
        composeRule.setContent {
            MethodScanCard(
                state = MethodScanUiState(phase = MethodScanPhase.Completed, mode = "sni_method_scan", report = report),
            )
        }
        composeRule.onNodeWithTag("method_scan_row_wrong_seq").assertIsDisplayed()
        composeRule.onNodeWithTag("method_scan_row_tls_frag").assertIsDisplayed()
    }

    @Test
    fun showsFailureMessage() {
        composeRule.setContent {
            MethodScanCard(
                state = MethodScanUiState(
                    phase = MethodScanPhase.Failed("Method scan failed: boom"),
                    mode = "sni_method_scan",
                ),
            )
        }
        composeRule.onNodeWithTag("method_scan_error").assertIsDisplayed()
    }
}
