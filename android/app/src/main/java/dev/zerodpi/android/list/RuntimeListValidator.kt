package dev.zerodpi.android.list

import dev.zerodpi.android.storage.RuntimeFileKind
import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress

data class RuntimeListIssue(
    val lineNumber: Int,
    val entry: String,
    val message: String,
)

data class RuntimeListValidation(
    val kind: RuntimeFileKind,
    val activeEntries: Int,
    val issues: List<RuntimeListIssue>,
    val warnings: List<String> = emptyList(),
) {
    val isValid: Boolean
        get() = issues.isEmpty()
}

object RuntimeListValidator {
    fun validate(
        kind: RuntimeFileKind,
        text: String,
        mode: String,
    ): RuntimeListValidation =
        when (kind) {
            RuntimeFileKind.Config -> RuntimeListValidation(
                kind = kind,
                activeEntries = 0,
                issues = emptyList(),
            )

            RuntimeFileKind.SniList -> validateSniList(text)
            RuntimeFileKind.IpList -> validateIpList(text, mode)
        }

    private fun validateSniList(text: String): RuntimeListValidation {
        val issues = mutableListOf<RuntimeListIssue>()
        var activeEntries = 0

        text.lineSequence().forEachIndexed { index, rawLine ->
            val entry = activeEntry(rawLine) ?: return@forEachIndexed
            activeEntries += 1
            val issue = validateHostname(entry)
            if (issue != null) {
                issues += RuntimeListIssue(
                    lineNumber = index + 1,
                    entry = entry,
                    message = issue,
                )
            }
        }

        return RuntimeListValidation(
            kind = RuntimeFileKind.SniList,
            activeEntries = activeEntries,
            issues = issues,
        )
    }

    private fun validateIpList(text: String, mode: String): RuntimeListValidation {
        val issues = mutableListOf<RuntimeListIssue>()
        var activeEntries = 0

        text.lineSequence().forEachIndexed { index, rawLine ->
            val entry = activeEntry(rawLine) ?: return@forEachIndexed
            activeEntries += 1
            val issue = validateIpOrCidr(entry)
            if (issue != null) {
                issues += RuntimeListIssue(
                    lineNumber = index + 1,
                    entry = entry,
                    message = issue,
                )
            }
        }

        val warnings = if (mode == MODE_IP_BYPASS_PLUS) {
            listOf("ip_bypass_plus is IPv4-only; use IPv4 addresses or IPv4 CIDR ranges for that mode.")
        } else {
            emptyList()
        }

        return RuntimeListValidation(
            kind = RuntimeFileKind.IpList,
            activeEntries = activeEntries,
            issues = issues,
            warnings = warnings,
        )
    }

    private fun activeEntry(line: String): String? {
        val trimmed = line.trim()
        return trimmed.takeIf { it.isNotEmpty() && !it.startsWith("#") }
    }

    private fun validateHostname(entry: String): String? {
        if (entry.any(Char::isWhitespace)) {
            return "Hostnames cannot contain whitespace."
        }
        if (entry.contains('/') || entry.contains(':')) {
            return "Enter one hostname only, without a scheme, port, or path."
        }
        if (isValidIpv4Literal(entry)) {
            return "Use a hostname, not an IP address."
        }

        val ascii = runCatching {
            IDN.toASCII(entry, IDN.USE_STD3_ASCII_RULES)
        }.getOrElse {
            return "Hostname contains characters that are not valid for SNI."
        }

        if (ascii.length !in 1..MAX_HOSTNAME_LENGTH) {
            return "Hostname must be 1 to $MAX_HOSTNAME_LENGTH characters."
        }
        if (ascii.startsWith(".") || ascii.endsWith(".")) {
            return "Hostname labels cannot be empty."
        }

        val labels = ascii.split('.')
        labels.forEach { label ->
            if (label.length !in 1..MAX_HOSTNAME_LABEL_LENGTH) {
                return "Each hostname label must be 1 to $MAX_HOSTNAME_LABEL_LENGTH characters."
            }
            if (!HOSTNAME_LABEL_REGEX.matches(label)) {
                return "Hostname labels must use letters, digits, and hyphens, and cannot start or end with a hyphen."
            }
        }

        return null
    }

    private fun validateIpOrCidr(entry: String): String? {
        if (entry.any(Char::isWhitespace)) {
            return "Entries cannot contain whitespace."
        }

        val slashCount = entry.count { it == '/' }
        if (slashCount == 0) {
            return if (isValidIpv4Literal(entry) || isValidIpv6Literal(entry)) {
                null
            } else {
                "Enter a valid IPv4 address, IPv6 address, or CIDR range."
            }
        }
        if (slashCount > 1) {
            return "CIDR entries must contain only one '/'."
        }

        val address = entry.substringBefore('/')
        val prefixText = entry.substringAfter('/')
        val prefix = prefixText.toIntOrNull()
            ?: return "CIDR prefix must be a number."

        return when {
            isValidIpv4Literal(address) -> {
                if (prefix in 0..IPV4_PREFIX_BITS) {
                    null
                } else {
                    "IPv4 CIDR prefix must be between 0 and $IPV4_PREFIX_BITS."
                }
            }

            isValidIpv6Literal(address) -> {
                if (prefix in 0..IPV6_PREFIX_BITS) {
                    null
                } else {
                    "IPv6 CIDR prefix must be between 0 and $IPV6_PREFIX_BITS."
                }
            }

            else -> "CIDR address must be a valid IPv4 or IPv6 literal."
        }
    }

    private fun isValidIpv4Literal(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) {
            return false
        }
        return parts.all { part ->
            part.isNotEmpty() &&
                part.all(Char::isDigit) &&
                part.toIntOrNull()?.let { it in 0..255 } == true
        }
    }

    private fun isValidIpv6Literal(value: String): Boolean {
        if (!value.contains(':') || value.contains('%')) {
            return false
        }
        return runCatching {
            InetAddress.getByName(value) is Inet6Address
        }.getOrDefault(false)
    }

    private const val MODE_IP_BYPASS_PLUS = "ip_bypass_plus"
    private const val MAX_HOSTNAME_LENGTH = 253
    private const val MAX_HOSTNAME_LABEL_LENGTH = 63
    private const val IPV4_PREFIX_BITS = 32
    private const val IPV6_PREFIX_BITS = 128
    private val HOSTNAME_LABEL_REGEX = Regex("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
}
