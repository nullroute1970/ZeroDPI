package dev.zerodpi.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Color(0xFF006B57),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF8CF8D8),
    onPrimaryContainer = Color(0xFF002019),
    secondary = Color(0xFF4B635B),
    secondaryContainer = Color(0xFFCDE8DD),
    background = Color(0xFFF5FBF7),
    surface = Color(0xFFF5FBF7),
    surfaceVariant = Color(0xFFDBE5DF),
    error = Color(0xFFBA1A1A),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF70DBBC),
    onPrimary = Color(0xFF00382C),
    primaryContainer = Color(0xFF005141),
    onPrimaryContainer = Color(0xFF8CF8D8),
    secondary = Color(0xFFB1CCC1),
    secondaryContainer = Color(0xFF334B43),
    background = Color(0xFF101411),
    surface = Color(0xFF101411),
    surfaceVariant = Color(0xFF404943),
    error = Color(0xFFFFB4AB),
)

@Composable
fun ZeroDpiTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}
