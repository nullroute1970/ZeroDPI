package dev.zerodpi.android.targetscan

object TargetPickPolicy {
    /** Run modes that scan a list at startup when nothing is pre-selected. */
    val pickableModes = setOf("sni_spoof", "ip_bypass", "ip_bypass_plus")

    /** The scan-only mode that probes the same list the run mode would scan. */
    fun scanModeFor(mode: String): String? =
        when (mode) {
            "sni_spoof" -> "sni_scan"
            "ip_bypass", "ip_bypass_plus" -> "ip_scan"
            else -> null
        }

    /** The kind of pinned target a run mode consumes. */
    fun pinKindForMode(mode: String): PinKind? =
        when (mode) {
            "sni_spoof" -> PinKind.Sni
            "ip_bypass", "ip_bypass_plus" -> PinKind.Ip
            else -> null
        }

    /**
     * True when a Start request must first run a scan and let the user pick:
     * AUTO_SELECT is off, the config has no manual SELECTED_* of the relevant
     * kind, and no stored pin of the mode-matching kind exists.
     */
    fun isGateEligible(
        mode: String,
        autoSelect: Boolean,
        selectedSni: String,
        selectedIp: String,
        pin: TargetPin?,
    ): Boolean {
        val expectedKind = pinKindForMode(mode) ?: return false
        val manualSelected = when (expectedKind) {
            PinKind.Sni -> selectedSni
            PinKind.Ip -> selectedIp
        }
        val hasMatchingPin = pin != null && pin.kind == expectedKind
        return !autoSelect && manualSelected.isBlank() && !hasMatchingPin
    }
}
