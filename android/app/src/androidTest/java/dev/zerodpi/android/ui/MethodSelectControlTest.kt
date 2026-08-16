package dev.zerodpi.android.ui

import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import dev.zerodpi.android.config.ConfigEditorState
import dev.zerodpi.android.config.ConfigFieldSchema
import dev.zerodpi.android.config.ConfigFieldType
import dev.zerodpi.android.config.ConfigRootImpact
import dev.zerodpi.android.config.ConfigSection
import dev.zerodpi.android.config.ZeroDpiConfigToml
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class MethodSelectControlTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val field = ConfigFieldSchema(
        name = "BYPASS_METHOD",
        type = ConfigFieldType.MultiSelect,
        defaultValue = "[\"wrong_seq\", \"tls_frag\"]",
        section = ConfigSection.BypassEngine,
        validationRule = "One or more methods.",
        rootImpact = ConfigRootImpact.ControlsRootRequirement,
        helpText = "Bypass methods.",
        options = listOf("wrong_seq", "tls_frag", "ccs_prefix"),
    )

    @Test
    fun rendersChecklistFromCanonicalValueAndEmitsToggles() {
        var lastChange: Pair<String, String>? = null
        val editor = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            BYPASS_METHOD = ["wrong_seq", "tls_frag"]
            """.trimIndent(),
        )
        composeRule.setContent {
            ConfigFieldControl(
                field = field,
                editorState = ConfigEditorState(
                    config = editor.config,
                    fieldText = editor.fieldText,
                    issues = editor.issues,
                    rootRequirement = editor.rootRequirement,
                ),
                enabled = true,
                onChanged = { name, value -> lastChange = name to value },
            )
        }
        composeRule.onNodeWithTag("method_select_wrong_seq").assertIsOn()
        composeRule.onNodeWithTag("method_select_tls_frag").assertIsOn()
        composeRule.onNodeWithTag("method_select_ccs_prefix").assertIsOff()
        composeRule.onNodeWithTag("method_select_ccs_prefix").performClick()
        composeRule.waitForIdle()
        assertEquals("BYPASS_METHOD", lastChange?.first)
        assertEquals("[\"wrong_seq\", \"tls_frag\", \"ccs_prefix\"]", lastChange?.second)
    }
}
