package dev.zerodpi.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Color(0xFF1C6E5C),
    onPrimary = Color.White,
    secondary = Color(0xFF546E7A),
    background = Color(0xFFF7FAF8),
    surface = Color(0xFFFDFEFC),
    surfaceVariant = Color(0xFFE8EFEA),
)

@Composable
fun ZeroDpiTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = LightColors,
        content = content,
    )
}
