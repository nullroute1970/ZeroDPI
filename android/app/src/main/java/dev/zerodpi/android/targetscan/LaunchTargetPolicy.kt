package dev.zerodpi.android.targetscan

import dev.zerodpi.android.config.ZeroDpiConfigToml

/**
 * Launch-time target policy.
 *
 * AUTO_SELECT=false means the user is responsible for the target: the stored
 * app pin may steer the run (the native binary then skips its startup scan)
 * and the app must never start a scan on its own. AUTO_SELECT=true keeps the
 * native auto-scan behavior, so a leftover app pin must not interfere.
 */
object LaunchTargetPolicy {
    /**
     * True when this launch may consume the stored app pin: a real run (no
     * mode override such as scan/test modes) whose config has AUTO_SELECT off.
     */
    fun consumesPin(configText: String, modeOverride: String?): Boolean {
        if (modeOverride != null) {
            return false
        }
        return ZeroDpiConfigToml.analyze(configText).valueFor("AUTO_SELECT") != "true"
    }
}
