package dev.zerodpi.android.config

import java.net.Inet6Address
import java.net.InetAddress

enum class ConfigSection(val title: String) {
    ProxyListener("Proxy listener"),
    OperatingMode("Operating mode"),
    InputFiles("Input files"),
    DnsResolution("DNS resolution"),
    ScanBehavior("Scan behavior"),
    ScannerTuning("Scanner tuning"),
    Scoring("Scoring"),
    BypassEngine("Bypass engine"),
    AndroidLinuxInterception("Android/Linux interception"),
    WrongSeq("wrong_seq"),
    WrongChecksum("wrong_checksum"),
    WrongMd5("wrong_md5"),
    WrongAck("wrong_ack"),
    WrongTimestamp("wrong_timestamp"),
    MethodScan("Method scan"),
    LowTtl("low_ttl"),
    FakeTls("fake_tls"),
    IpFrag("ip_frag"),
    Disorder("disorder"),
    UrgSniSplit("urg_sni_split"),
    SniBoundaryFrag("sni_boundary_frag"),
    TlsPadding("tls_padding"),
    MixedCaseSni("mixed_case_sni"),
    CcsPrefix("ccs_prefix"),
    TlsRecordFrag("tls_record_frag"),
    TlsFrag("tls_frag"),
    ProxyScan("Proxy scan"),
}

enum class ConfigFieldType(val label: String) {
    Text("text"),
    OptionalText("optional text"),
    Boolean("boolean"),
    UInt8("0-255 integer"),
    UInt16("0-65535 integer"),
    UInt32("0-4294967295 integer"),
    UInt64("non-negative integer"),
    USize("non-negative integer"),
    Float("number"),
    Enum("choice"),
    IntegerRange("integer or range"),
    PacketSelector("packet selector"),
    MultiSelect("method list"),
}

enum class ConfigRootImpact(val label: String) {
    None("No root impact"),
    ControlsRootRequirement("Changes whether Start needs root"),
    PacketInterceptionOnly("Used by packet interception modes that need root"),
    RootlessFragmentation("Can be used by rootless tls_frag workflows"),
}

data class ConfigFieldSchema(
    val name: String,
    val type: ConfigFieldType,
    val defaultValue: String,
    val section: ConfigSection,
    val validationRule: String,
    val rootImpact: ConfigRootImpact,
    val helpText: String,
    val options: List<String> = emptyList(),
    val required: Boolean = false,
)

sealed interface ConfigValue {
    val displayText: String
}

data class TextConfigValue(val value: String) : ConfigValue {
    override val displayText: String = value
}

data class BooleanConfigValue(val value: Boolean) : ConfigValue {
    override val displayText: String = value.toString()
}

data class IntegerConfigValue(val value: Long) : ConfigValue {
    override val displayText: String = value.toString()
}

data class FloatConfigValue(val value: Double) : ConfigValue {
    override val displayText: String = value.toString()
}

data class ZeroDpiConfig(
    private val values: Map<String, ConfigValue>,
) {
    fun text(name: String): String =
        (values[name] as? TextConfigValue)?.value.orEmpty()

    fun methodList(name: String): List<String> =
        parseTomlStringArray(text(name)) ?: emptyList()

    fun boolean(name: String): Boolean =
        (values[name] as? BooleanConfigValue)?.value ?: false

    fun integer(name: String): Long =
        (values[name] as? IntegerConfigValue)?.value ?: 0L

    fun decimal(name: String): Double =
        (values[name] as? FloatConfigValue)?.value ?: 0.0
}

data class ConfigValidationIssue(
    val fieldName: String?,
    val message: String,
)

data class RootRequirementInfo(
    val requiresRoot: Boolean,
    val message: String,
    val alternatives: List<String>,
)

data class ConfigEditorState(
    val config: ZeroDpiConfig,
    val fieldText: Map<String, String>,
    val issues: List<ConfigValidationIssue>,
    val rootRequirement: RootRequirementInfo,
) {
    val canStart: Boolean
        get() = issues.isEmpty()

    fun valueFor(fieldName: String): String =
        fieldText[fieldName].orEmpty()

    fun issuesFor(fieldName: String): List<ConfigValidationIssue> =
        issues.filter { it.fieldName == fieldName }
}

internal fun expandMethodAlias(name: String): List<String> =
    when (name) {
        "wrong_seq_wrong_md5" -> listOf("wrong_seq", "wrong_md5")
        "wrong_seq_tls_frag" -> listOf("wrong_seq", "tls_frag")
        "wrong_md5_tls_frag" -> listOf("wrong_md5", "tls_frag")
        "wrong_seq_tls_record_frag" -> listOf("wrong_seq", "tls_record_frag")
        else -> listOf(name)
    }

internal fun canonicalMethodArray(methods: List<String>): String =
    methods.joinToString(prefix = "[", separator = ", ", postfix = "]") { "\"$it\"" }

internal fun parseTomlStringArray(raw: String): List<String>? {
    val trimmed = raw.trim()
    if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) return null
    val body = trimmed.substring(1, trimmed.length - 1)
    val items = mutableListOf<String>()
    var index = 0
    while (true) {
        while (index < body.length && body[index].isWhitespace()) index += 1
        if (index >= body.length) break
        if (body[index] != '"') return null
        index += 1
        val builder = StringBuilder()
        var closed = false
        while (index < body.length) {
            when (val char = body[index]) {
                '"' -> {
                    closed = true
                    index += 1
                    break
                }
                '\\' -> {
                    if (index + 1 >= body.length) return null
                    builder.append(
                        when (body[index + 1]) {
                            'n' -> '\n'
                            't' -> '\t'
                            'r' -> '\r'
                            '"' -> '"'
                            '\\' -> '\\'
                            else -> return null
                        },
                    )
                    index += 2
                }
                else -> {
                    builder.append(char)
                    index += 1
                }
            }
        }
        if (!closed) return null
        items += builder.toString()
        while (index < body.length && body[index].isWhitespace()) index += 1
        if (index >= body.length) break
        if (body[index] != ',') return null
        index += 1
        var next = index
        while (next < body.length && body[next].isWhitespace()) next += 1
        if (next >= body.length) return null
    }
    return items
}

internal fun validateSniPosition(value: String, allowedWords: Set<String>): String? {
    val trimmed = value.trim()
    return when {
        trimmed in allowedWords -> null
        trimmed.toLongOrNull()?.let { it >= 0 } == true -> null
        else -> "must be one of ${allowedWords.joinToString()} or a non-negative index."
    }
}

object ZeroDpiConfigSchema {
    val modeOptions = listOf(
        "sni_spoof",
        "ip_bypass",
        "ip_bypass_plus",
        "sni_scan",
        "ip_scan",
        "proxy_scan",
        "sni_method_scan",
        "ip_method_scan",
    )

    val methodScanModes = setOf("sni_method_scan", "ip_method_scan")

    val baseBypassMethods = listOf(
        "wrong_seq",
        "wrong_ack",
        "wrong_checksum",
        "wrong_md5",
        "wrong_timestamp",
        "low_ttl",
        "tls_record_frag",
        "fake_tls",
        "ip_frag",
        "disorder",
        "tls_frag",
        "ccs_prefix",
        "tls_padding",
        "mixed_case_sni",
        "urg_sni_split",
        "sni_boundary_frag",
    )

    val firewallBackendOptions = listOf("iptables", "nftables")

    val fields: List<ConfigFieldSchema> = listOf(
        field(
            name = "LISTEN_HOST",
            type = ConfigFieldType.Text,
            defaultValue = "127.0.0.1",
            section = ConfigSection.ProxyListener,
            validationRule = "A host or IP address accepted by ZeroDPI.",
            helpText = "Local address the proxy listens on.",
            required = true,
        ),
        field(
            name = "LISTEN_PORT",
            type = ConfigFieldType.UInt16,
            defaultValue = "44444",
            section = ConfigSection.ProxyListener,
            validationRule = "TCP port from 0 to 65535.",
            helpText = "Port your upstream VPN app should connect to.",
            required = true,
        ),
        field(
            name = "MODE",
            type = ConfigFieldType.Enum,
            defaultValue = "sni_spoof",
            section = ConfigSection.OperatingMode,
            validationRule = "Must be one of the supported mode strings.",
            rootImpact = ConfigRootImpact.ControlsRootRequirement,
            helpText = "Chooses scan, relay, or SNI-spoof operation.",
            options = modeOptions,
        ),
        field(
            name = "AUTO_SELECT",
            type = ConfigFieldType.Boolean,
            defaultValue = "false",
            section = ConfigSection.OperatingMode,
            validationRule = "true or false.",
            helpText = "Automatically pick the highest-ranked scan result.",
        ),
        field(
            name = "SELECTED_SNI",
            type = ConfigFieldType.OptionalText,
            defaultValue = "",
            section = ConfigSection.OperatingMode,
            validationRule = "Empty or at most 219 UTF-8 bytes.",
            helpText = "When set, skips SNI scanning and resolves this hostname.",
        ),
        field(
            name = "SELECTED_IP",
            type = ConfigFieldType.OptionalText,
            defaultValue = "",
            section = ConfigSection.OperatingMode,
            validationRule = "Empty or a valid IP address. ip_bypass_plus accepts IPv4 only.",
            helpText = "When set, skips IP scanning and uses this address.",
        ),
        field(
            name = "SNI_LIST",
            type = ConfigFieldType.Text,
            defaultValue = "sni_list.txt",
            section = ConfigSection.InputFiles,
            validationRule = "Relative or absolute path.",
            helpText = "Path to candidate hostnames.",
        ),
        field(
            name = "CUSTOM_DNS_ENABLED",
            type = ConfigFieldType.Boolean,
            defaultValue = "false",
            section = ConfigSection.DnsResolution,
            validationRule = "true or false.",
            helpText = "Resolve SNI hostnames through a custom plain-DNS server.",
        ),
        field(
            name = "CUSTOM_DNS_SERVER",
            type = ConfigFieldType.OptionalText,
            defaultValue = "",
            section = ConfigSection.DnsResolution,
            validationRule = "When enabled, a literal IPv4/IPv6 address with an optional non-zero port.",
            helpText = "Custom DNS endpoint; omitted ports default to 53.",
        ),
        field(
            name = "IP_LIST",
            type = ConfigFieldType.Text,
            defaultValue = "ip_list.txt",
            section = ConfigSection.InputFiles,
            validationRule = "Relative or absolute path.",
            helpText = "Path to candidate IPs and CIDR ranges.",
        ),
        field(
            name = "SCAN_TIMEOUT_SECS",
            type = ConfigFieldType.UInt64,
            defaultValue = "5",
            section = ConfigSection.ScanBehavior,
            validationRule = "Must be greater than 0.",
            helpText = "Per-probe timeout in seconds.",
        ),
        field(
            name = "RESCAN_INTERVAL_SECS",
            type = ConfigFieldType.UInt64,
            defaultValue = "0",
            section = ConfigSection.ScanBehavior,
            validationRule = "0 disables periodic rescans.",
            helpText = "Background SNI rescan interval while running.",
        ),
        field(
            name = "SNI_SWITCH_MIN_SCORE",
            type = ConfigFieldType.UInt8,
            defaultValue = "1",
            section = ConfigSection.ScanBehavior,
            validationRule = "Must be at most 100.",
            helpText = "Minimum score needed before a background rescan switches target.",
        ),
        field(
            name = "SCAN_OUTPUT",
            type = ConfigFieldType.OptionalText,
            defaultValue = "",
            section = ConfigSection.ScanBehavior,
            validationRule = "Empty or a relative/absolute output path.",
            helpText = "Optional JSON file for scan-only results.",
        ),
        field(
            name = "SNI_MAX_CONCURRENT",
            type = ConfigFieldType.USize,
            defaultValue = "64",
            section = ConfigSection.ScannerTuning,
            validationRule = "Non-negative integer.",
            helpText = "Maximum concurrent SNI probes.",
        ),
        field(
            name = "IP_MAX_P1_CONCURRENT",
            type = ConfigFieldType.USize,
            defaultValue = "128",
            section = ConfigSection.ScannerTuning,
            validationRule = "Non-negative integer.",
            helpText = "Maximum concurrent TCP probes in IP scan phase 1.",
        ),
        field(
            name = "IP_MAX_P2_CONCURRENT",
            type = ConfigFieldType.USize,
            defaultValue = "32",
            section = ConfigSection.ScannerTuning,
            validationRule = "Non-negative integer.",
            helpText = "Maximum concurrent TLS probes in IP scan phase 2.",
        ),
        field(
            name = "SCAN_DOWNLOAD_CAP",
            type = ConfigFieldType.USize,
            defaultValue = "10240",
            section = ConfigSection.ScannerTuning,
            validationRule = "Must be greater than 0.",
            helpText = "Maximum bytes downloaded for speed tests.",
        ),
        field(
            name = "SCAN_UPLOAD_CAP",
            type = ConfigFieldType.USize,
            defaultValue = "10240",
            section = ConfigSection.ScannerTuning,
            validationRule = "Must be greater than 0.",
            helpText = "Maximum bytes uploaded for upload speed tests.",
        ),
        field(
            name = "SCAN_UPLOAD_PATH",
            type = ConfigFieldType.Text,
            defaultValue = "/",
            section = ConfigSection.ScannerTuning,
            validationRule = "Must start with / and contain no CR/LF.",
            helpText = "HTTP path used for upload speed tests.",
        ),
        field(
            name = "IP_SCAN_SNI",
            type = ConfigFieldType.Text,
            defaultValue = "cloudflare.com",
            section = ConfigSection.ScannerTuning,
            validationRule = "Non-empty hostname string.",
            helpText = "SNI used only during IP scan TLS probes.",
        ),
        field(
            name = "IPV6_MAX_HOSTS",
            type = ConfigFieldType.UInt64,
            defaultValue = "65536",
            section = ConfigSection.ScannerTuning,
            validationRule = "Non-negative integer.",
            helpText = "Maximum hosts expanded from one IPv6 CIDR block.",
        ),
        field(
            name = "TCP_LATENCY_CAP_MS",
            type = ConfigFieldType.Float,
            defaultValue = "500.0",
            section = ConfigSection.Scoring,
            validationRule = "Finite number.",
            helpText = "TCP latency cap used for scan scoring.",
        ),
        field(
            name = "TLS_LATENCY_CAP_MS",
            type = ConfigFieldType.Float,
            defaultValue = "1000.0",
            section = ConfigSection.Scoring,
            validationRule = "Finite number.",
            helpText = "TLS latency cap used for scan scoring.",
        ),
        field(
            name = "TTFB_CAP_MS",
            type = ConfigFieldType.Float,
            defaultValue = "2000.0",
            section = ConfigSection.Scoring,
            validationRule = "Finite number.",
            helpText = "Time-to-first-byte cap used for scan scoring.",
        ),
        field(
            name = "SPEED_CAP_BPS",
            type = ConfigFieldType.Float,
            defaultValue = "2048000.0",
            section = ConfigSection.Scoring,
            validationRule = "Must be finite and greater than 0.",
            helpText = "Download speed cap for scan scoring.",
        ),
        field(
            name = "UPLOAD_SPEED_CAP_BPS",
            type = ConfigFieldType.Float,
            defaultValue = "2048000.0",
            section = ConfigSection.Scoring,
            validationRule = "Must be finite and greater than 0.",
            helpText = "Upload speed cap for scan scoring.",
        ),
        field(
            name = "BYPASS_METHOD",
            type = ConfigFieldType.MultiSelect,
            defaultValue = canonicalMethodArray(listOf("wrong_seq", "tls_frag")),
            section = ConfigSection.BypassEngine,
            validationRule = "One or more methods; see combo restrictions in config.toml.",
            rootImpact = ConfigRootImpact.ControlsRootRequirement,
            helpText = "Bypass methods applied by SNI, proxy, and method-scan modes. Socket-only methods (tls_frag, ccs_prefix, tls_padding, mixed_case_sni, sni_boundary_frag) need no root.",
            options = baseBypassMethods,
        ),
        field(
            name = "BYPASS_TIMEOUT_SECS",
            type = ConfigFieldType.UInt64,
            defaultValue = "20",
            section = ConfigSection.BypassEngine,
            validationRule = "Must be greater than 0.",
            helpText = "Seconds to wait for bypass completion before failing a connection.",
        ),
        field(
            name = "RELAY_MAX_LIFETIME_SECS",
            type = ConfigFieldType.UInt64,
            defaultValue = "0",
            section = ConfigSection.BypassEngine,
            validationRule = "0 disables relay rotation.",
            helpText = "Maximum established relay lifetime before reconnect.",
        ),
        field(
            name = "NFQUEUE_NUM",
            type = ConfigFieldType.UInt16,
            defaultValue = "1",
            section = ConfigSection.AndroidLinuxInterception,
            validationRule = "Queue number from 0 to 65535.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "NFQUEUE queue number used by Android/Linux interception.",
        ),
        field(
            name = "LINUX_FIREWALL_BACKEND",
            type = ConfigFieldType.Enum,
            defaultValue = "iptables",
            section = ConfigSection.AndroidLinuxInterception,
            validationRule = "Must be iptables or nftables.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Firewall command ZeroDPI uses for NFQUEUE rules.",
            options = firewallBackendOptions,
        ),
        field(
            name = "WRONG_SEQ_EXTRA_OFFSET",
            type = ConfigFieldType.UInt32,
            defaultValue = "0",
            section = ConfigSection.WrongSeq,
            validationRule = "Non-negative integer up to u32::MAX.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Extra offset subtracted from the fake packet sequence number.",
        ),
        field(
            name = "WRONG_SEQ_SET_PSH",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongSeq,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Set TCP PSH on wrong-sequence fake packets.",
        ),
        field(
            name = "WRONG_SEQ_BUMP_IP_IDENT",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongSeq,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Increment IPv4 Identification on wrong-sequence fake packets.",
        ),
        field(
            name = "WRONG_CHECKSUM_DELTA",
            type = ConfigFieldType.UInt16,
            defaultValue = "1",
            section = ConfigSection.WrongChecksum,
            validationRule = "Must be at least 1.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Value added to corrupt the spoofed packet TCP checksum.",
        ),
        field(
            name = "WRONG_CHECKSUM_SET_PSH",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongChecksum,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Set TCP PSH on wrong-checksum fake packets.",
        ),
        field(
            name = "WRONG_CHECKSUM_BUMP_IP_IDENT",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongChecksum,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Increment IPv4 Identification on wrong-checksum fake packets.",
        ),
        field(
            name = "WRONG_CHECKSUM_COMPLETE_IMMEDIATELY",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongChecksum,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Treat the checksum bypass as complete after the fake packet is sent.",
        ),
        field(
            name = "WRONG_MD5_SET_PSH",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongMd5,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Set TCP PSH on TCP-MD5 fake packets.",
        ),
        field(
            name = "WRONG_MD5_BUMP_IP_IDENT",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongMd5,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Increment IPv4 Identification on TCP-MD5 fake packets.",
        ),
        field(
            name = "WRONG_MD5_COMPLETE_IMMEDIATELY",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongMd5,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Treat the TCP-MD5 bypass as complete after the fake packet is sent.",
        ),
        field(
            name = "WRONG_ACK_OFFSET",
            type = ConfigFieldType.UInt32,
            defaultValue = "1",
            section = ConfigSection.WrongAck,
            validationRule = "Must be at least 1.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Bytes subtracted from the spoofed TCP ACK number.",
        ),
        field(
            name = "WRONG_ACK_SET_PSH",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongAck,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Set TCP PSH on wrong-ACK fake packets.",
        ),
        field(
            name = "WRONG_ACK_BUMP_IP_IDENT",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongAck,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Increment IPv4 Identification on wrong-ACK fake packets.",
        ),
        field(
            name = "WRONG_ACK_COMPLETE_IMMEDIATELY",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongAck,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Treat the wrong-ACK bypass as complete after the fake packet is sent.",
        ),
        field(
            name = "WRONG_TIMESTAMP_OFFSET",
            type = ConfigFieldType.UInt32,
            defaultValue = "1",
            section = ConfigSection.WrongTimestamp,
            validationRule = "Must be at least 1.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Value subtracted from TCP Timestamp TSval on fake packets.",
        ),
        field(
            name = "WRONG_TIMESTAMP_SET_PSH",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongTimestamp,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Set TCP PSH on wrong-timestamp fake packets.",
        ),
        field(
            name = "WRONG_TIMESTAMP_BUMP_IP_IDENT",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongTimestamp,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Increment IPv4 Identification on wrong-timestamp fake packets.",
        ),
        field(
            name = "WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.WrongTimestamp,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Treat the wrong-timestamp bypass as complete after the fake packet is sent.",
        ),
        field(
            name = "TLS_RECORD_FRAG_SIZE",
            type = ConfigFieldType.USize,
            defaultValue = "1",
            section = ConfigSection.TlsRecordFrag,
            validationRule = "Must be at least 1.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Maximum bytes per TLS record body fragment.",
        ),
        field(
            name = "TLS_RECORD_FRAG_SET_PSH",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.TlsRecordFrag,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Set TCP PSH on TLS-record-fragmented packets.",
        ),
        field(
            name = "TLS_RECORD_FRAG_BUMP_IP_IDENT",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.TlsRecordFrag,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Increment IPv4 Identification on TLS-record-fragmented packets.",
        ),
        field(
            name = "TLS_FRAG_PACKETS",
            type = ConfigFieldType.PacketSelector,
            defaultValue = "1-3",
            section = ConfigSection.TlsFrag,
            validationRule = "tlshello, a 1-based index, or a 1-based range.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Which client writes are fragmented by tls_frag.",
        ),
        field(
            name = "TLS_FRAG_LENGTH",
            type = ConfigFieldType.IntegerRange,
            defaultValue = "100-200",
            section = ConfigSection.TlsFrag,
            validationRule = "Integer or inclusive range with minimum at least 1.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "TCP-level fragment length or length range.",
        ),
        field(
            name = "TLS_FRAG_INTERVAL_MS",
            type = ConfigFieldType.IntegerRange,
            defaultValue = "10-20",
            section = ConfigSection.TlsFrag,
            validationRule = "Integer or inclusive range with minimum at least 0.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Delay between TCP-level fragments.",
        ),
        field(
            name = "TCP_SEG_SIZE",
            type = ConfigFieldType.USize,
            defaultValue = "1",
            section = ConfigSection.TlsFrag,
            validationRule = "Must be from 1 through i32::MAX.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Legacy fixed fragment length fallback.",
        ),
        field(
            name = "TCP_SEG_NODELAY",
            type = ConfigFieldType.Boolean,
            defaultValue = "true",
            section = ConfigSection.TlsFrag,
            validationRule = "true or false.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Set TCP_NODELAY before writing small fragments.",
        ),
        field(
            name = "PROXY_TEST_MIN_SNI_SCORE",
            type = ConfigFieldType.UInt8,
            defaultValue = "1",
            section = ConfigSection.ProxyScan,
            validationRule = "0-255 integer.",
            helpText = "Minimum phase-1 score before proxy testing.",
        ),
        field(
            name = "PROXY_TEST_TOP_N",
            type = ConfigFieldType.USize,
            defaultValue = "0",
            section = ConfigSection.ProxyScan,
            validationRule = "0 means no cap.",
            helpText = "Maximum phase-1 candidates carried into proxy testing.",
        ),
        field(
            name = "PROXY_TEST_SOCKS5_HOST",
            type = ConfigFieldType.Text,
            defaultValue = "127.0.0.1",
            section = ConfigSection.ProxyScan,
            validationRule = "SOCKS5 proxy host string.",
            helpText = "Host of the SOCKS5 proxy used by proxy_scan.",
        ),
        field(
            name = "PROXY_TEST_SOCKS5_PORT",
            type = ConfigFieldType.UInt16,
            defaultValue = "10808",
            section = ConfigSection.ProxyScan,
            validationRule = "TCP port from 0 to 65535.",
            helpText = "SOCKS5 proxy port used by proxy_scan.",
        ),
        field(
            name = "PROXY_TEST_URL",
            type = ConfigFieldType.Text,
            defaultValue = "https://speed.cloudflare.com/__down?bytes=524288",
            section = ConfigSection.ProxyScan,
            validationRule = "HTTPS URL string.",
            helpText = "URL fetched through the proxy for speed and latency tests.",
        ),
        field(
            name = "PROXY_TEST_TIMEOUT_SECS",
            type = ConfigFieldType.UInt64,
            defaultValue = "30",
            section = ConfigSection.ProxyScan,
            validationRule = "Must be greater than 0.",
            helpText = "Per-probe timeout for proxy_scan phase 2.",
        ),
        field(
            name = "PROXY_TEST_SNI_WEIGHT",
            type = ConfigFieldType.Float,
            defaultValue = "0.5",
            section = ConfigSection.ProxyScan,
            validationRule = "Must be in [0.0, 1.0].",
            helpText = "Blend weight for the phase-1 SNI scan score.",
        ),
        field(
            name = "PROXY_TEST_LATENCY_CAP_MS",
            type = ConfigFieldType.Float,
            defaultValue = "500.0",
            section = ConfigSection.ProxyScan,
            validationRule = "Finite number.",
            helpText = "TCP latency cap for proxy_scan scoring.",
        ),
        field(
            name = "PROXY_TEST_TTFB_CAP_MS",
            type = ConfigFieldType.Float,
            defaultValue = "3000.0",
            section = ConfigSection.ProxyScan,
            validationRule = "Finite number.",
            helpText = "TTFB cap for proxy_scan scoring.",
        ),
        field(
            name = "PROXY_TEST_SPEED_CAP_BPS",
            type = ConfigFieldType.Float,
            defaultValue = "2048000.0",
            section = ConfigSection.ProxyScan,
            validationRule = "Finite number.",
            helpText = "Download speed cap for proxy_scan scoring.",
        ),
        field(name = "METHOD_SCAN_METHODS", type = ConfigFieldType.MultiSelect,
            defaultValue = canonicalMethodArray(baseBypassMethods), section = ConfigSection.MethodScan,
            validationRule = "One or more base methods; no duplicates.",
            helpText = "Bypass methods tested by sni_method_scan / ip_method_scan.", options = baseBypassMethods),
        field(name = "METHOD_SCAN_SAMPLES", type = ConfigFieldType.USize, defaultValue = "3",
            section = ConfigSection.MethodScan, validationRule = "Must be >= 1.",
            helpText = "Probe samples per method."),
        field(name = "METHOD_SCAN_INTERVAL_MS", type = ConfigFieldType.UInt64, defaultValue = "1000",
            section = ConfigSection.MethodScan, validationRule = "Non-negative integer.",
            helpText = "Interval between samples; 0 = back-to-back."),
        field(name = "METHOD_SCAN_TIMEOUT_SECS", type = ConfigFieldType.UInt64, defaultValue = "10",
            section = ConfigSection.MethodScan, validationRule = "Must be > 0.",
            helpText = "Per-probe timeout for method-scan probes."),
        field(name = "METHOD_SCAN_OUTPUT", type = ConfigFieldType.OptionalText, defaultValue = "",
            section = ConfigSection.MethodScan, validationRule = "Empty or a relative/absolute JSON output path.",
            helpText = "Optional JSON file for method-scan results."),
        field(name = "LOW_TTL_VALUE", type = ConfigFieldType.UInt8, defaultValue = "5",
            section = ConfigSection.LowTtl, validationRule = "Must be from 1 through 64.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "IP TTL stamped on low_ttl decoy packets."),
        field(name = "LOW_TTL_SET_PSH", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.LowTtl, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Set TCP PSH on low_ttl decoy packets."),
        field(name = "LOW_TTL_BUMP_IP_IDENT", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.LowTtl, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Increment IPv4 Identification on low_ttl decoy packets."),
        field(name = "LOW_TTL_COMPLETE_IMMEDIATELY", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.LowTtl, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Treat the low_ttl bypass as complete after the decoy is sent."),
        field(name = "LOW_TTL_DISCOVER", type = ConfigFieldType.Boolean, defaultValue = "false",
            section = ConfigSection.LowTtl, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Auto-discover the correct LOW_TTL_VALUE at startup."),
        field(name = "LOW_TTL_DISCOVER_MAX", type = ConfigFieldType.UInt8, defaultValue = "32",
            section = ConfigSection.LowTtl, validationRule = "Must be from 1 through 64.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Upper bound of the LOW_TTL_DISCOVER search range."),
        field(name = "LOW_TTL_DISCOVER_TIMEOUT_MS", type = ConfigFieldType.UInt64, defaultValue = "5000",
            section = ConfigSection.LowTtl, validationRule = "Must be >= 100.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Per-candidate timeout for LOW_TTL_DISCOVER probes."),
        field(name = "FAKE_TLS_EXTRA_OFFSET", type = ConfigFieldType.UInt32, defaultValue = "0",
            section = ConfigSection.FakeTls, validationRule = "Non-negative integer up to u32::MAX.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Extra offset behind the fake_tls sequence number."),
        field(name = "FAKE_TLS_SET_PSH", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.FakeTls, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Set TCP PSH on fake_tls decoy packets."),
        field(name = "FAKE_TLS_BUMP_IP_IDENT", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.FakeTls, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Increment IPv4 Identification on fake_tls decoy packets."),
        field(name = "FAKE_TLS_COMPLETE_IMMEDIATELY", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.FakeTls, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Treat the fake_tls bypass as complete after the decoy is sent."),
        field(name = "FAKE_TLS_FORWARD_REAL", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.FakeTls, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Forward the real ClientHello behind the fake_tls decoy."),
        field(name = "IP_FRAG_SIZE", type = ConfigFieldType.USize, defaultValue = "24",
            section = ConfigSection.IpFrag, validationRule = "Must be >= 8 and a multiple of 8.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Maximum IP payload bytes per ip_frag fragment."),
        field(name = "IP_FRAG_ONLY_FIRST_PACKET", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.IpFrag, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Fragment only the first outbound data packet (false = fragment-all)."),
        field(name = "DISORDER_SEGMENTS", type = ConfigFieldType.USize, defaultValue = "2",
            section = ConfigSection.Disorder, validationRule = "Must be 2 or 3.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "TCP segments disorder splits each packet into."),
        field(name = "DISORDER_DELAY_MS", type = ConfigFieldType.UInt64, defaultValue = "0",
            section = ConfigSection.Disorder, validationRule = "Must be <= 1000.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Delay between disorder segment emissions."),
        field(name = "DISORDER_REVERSE", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.Disorder, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Emit disorder segments in reverse order."),
        field(name = "DISORDER_ONLY_FIRST_PACKET", type = ConfigFieldType.Boolean, defaultValue = "true",
            section = ConfigSection.Disorder, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Re-chunk only the first outbound data packet (false = fragment-all)."),
        field(name = "SNI_SPLIT_DUMMY_BYTE", type = ConfigFieldType.UInt8, defaultValue = "0",
            section = ConfigSection.UrgSniSplit, validationRule = "0-255 integer.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Dummy byte urg_sni_split splices into the SNI."),
        field(name = "SNI_SPLIT_POSITION", type = ConfigFieldType.Text, defaultValue = "middle",
            section = ConfigSection.UrgSniSplit,
            validationRule = "middle, start, end, or a 0-based index.",
            rootImpact = ConfigRootImpact.PacketInterceptionOnly,
            helpText = "Where urg_sni_split inserts the dummy byte."),
        field(name = "SNI_BOUNDARY_FRAG_SPLIT_POINT", type = ConfigFieldType.Text, defaultValue = "extension_length",
            section = ConfigSection.SniBoundaryFrag,
            validationRule = "extension_length, middle, or a 0-based index.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Where sni_boundary_frag cuts the first ClientHello write."),
        field(name = "SNI_BOUNDARY_FRAG_DELAY_MS", type = ConfigFieldType.IntegerRange, defaultValue = "5-10",
            section = ConfigSection.SniBoundaryFrag, validationRule = "Integer or range with minimum >= 0.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Delay between the two boundary-split TCP segments."),
        field(name = "TLS_PADDING_SIZE", type = ConfigFieldType.IntegerRange, defaultValue = "1500-2500",
            section = ConfigSection.TlsPadding, validationRule = "Integer or range; minimum >= 1, maximum <= 16000.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Padding extension size inserted by tls_padding."),
        field(name = "TLS_PADDING_POSITION", type = ConfigFieldType.Enum, defaultValue = "before",
            section = ConfigSection.TlsPadding, validationRule = "Must be before or after.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Insert padding before or after the SNI extension.",
            options = listOf("before", "after")),
        field(name = "MIXED_CASE_SNI_FLIP_ALL", type = ConfigFieldType.Boolean, defaultValue = "false",
            section = ConfigSection.MixedCaseSni, validationRule = "true or false.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Randomize case of every SNI letter (not just a subset)."),
        field(name = "CCS_PREFIX_RECORD_VERSION", type = ConfigFieldType.Text, defaultValue = "0x0303",
            section = ConfigSection.CcsPrefix, validationRule = "Two hex bytes, 0x prefix optional.",
            rootImpact = ConfigRootImpact.RootlessFragmentation,
            helpText = "Record-version bytes of the ccs_prefix ChangeCipherSpec record."),
    )

    val fieldsByName: Map<String, ConfigFieldSchema> =
        fields.associateBy { it.name }

    val sections: List<ConfigSection> =
        fields.map { it.section }.distinct()

    fun fieldsIn(section: ConfigSection): List<ConfigFieldSchema> =
        fields.filter { it.section == section }

    private fun field(
        name: String,
        type: ConfigFieldType,
        defaultValue: String,
        section: ConfigSection,
        validationRule: String,
        helpText: String,
        rootImpact: ConfigRootImpact = ConfigRootImpact.None,
        options: List<String> = emptyList(),
        required: Boolean = false,
    ): ConfigFieldSchema =
        ConfigFieldSchema(
            name = name,
            type = type,
            defaultValue = defaultValue,
            section = section,
            validationRule = validationRule,
            rootImpact = rootImpact,
            helpText = helpText,
            options = options,
            required = required,
        )
}

object ZeroDpiConfigToml {
    private const val MAX_SNI_LEN_BYTES = 219
    private val assignmentPattern = Regex("""^\s*([A-Z0-9_]+)\s*=""")
    private val keyValuePattern = Regex("""^\s*([A-Za-z0-9_]+)\s*=""")
    private val integerRangePattern = Regex("""^\s*(-?\d+)(?:\s*-\s*(-?\d+))?\s*$""")
    private val packetRangePattern = Regex("""^\s*(\d+)(?:\s*-\s*(\d+))?\s*$""")

    fun analyze(text: String): ConfigEditorState {
        val parsedText = parseFieldText(text)
        val issues = parsedText.issues.toMutableList()
        val invalidFields = issues.mapNotNull { it.fieldName }.toMutableSet()
        val values = mutableMapOf<String, ConfigValue>()

        ZeroDpiConfigSchema.fields.forEach { schema ->
            val valueText = parsedText.fieldText[schema.name] ?: schema.defaultValue
            val parsed = parseValue(schema, valueText)
            if (parsed.issue != null) {
                issues += ConfigValidationIssue(schema.name, parsed.issue)
                invalidFields += schema.name
            }
            values[schema.name] = parsed.value ?: defaultValueFor(schema)
        }

        val config = ZeroDpiConfig(values)
        addRustValidationIssues(config, invalidFields, issues)

        return ConfigEditorState(
            config = config,
            fieldText = parsedText.fieldText,
            issues = issues,
            rootRequirement = rootRequirementFor(config, issues),
        )
    }

    fun methodScanStartConfigText(configText: String): String {
        val editor = analyze(configText)
        val mode = editor.valueFor("MODE")
        if (mode !in ZeroDpiConfigSchema.methodScanModes) return configText
        return if (editor.valueFor("METHOD_SCAN_OUTPUT").isBlank()) {
            replaceOrAppendField(configText, "METHOD_SCAN_OUTPUT", "method_scan_output.json")
        } else {
            configText
        }
    }

    fun replaceOrAppendField(text: String, fieldName: String, value: String): String {
        val schema = ZeroDpiConfigSchema.fieldsByName[fieldName] ?: return text
        val replacementValue = toTomlLiteral(schema, value)
        val lines = text.split('\n').toMutableList()
        var replaced = false

        for (index in lines.indices) {
            val line = lines[index]
            if (assignmentPattern.find(line)?.groupValues?.get(1) == fieldName) {
                val comment = trailingComment(line.substringAfter('=', missingDelimiterValue = ""))
                lines[index] = if (comment.isBlank()) {
                    "$fieldName = $replacementValue"
                } else {
                    "$fieldName = $replacementValue $comment"
                }
                replaced = true
                break
            }
        }

        if (!replaced) {
            if (lines.isNotEmpty() && lines.last().isNotEmpty()) {
                lines += ""
            }
            lines += "$fieldName = $replacementValue"
        }

        return lines.joinToString("\n")
    }

    fun requiresPacketInterception(mode: String, bypassMethods: Set<String>): Boolean {
        val needsInterceptor = bypassMethods.any { it !in socketOnlyMethods }
        return when (mode) {
            "sni_spoof", "proxy_scan", "ip_bypass_plus", "sni_method_scan", "ip_method_scan" -> needsInterceptor
            else -> false
        }
    }

    fun validateMethodCombination(methods: List<String>): String? {
        fun has(vararg names: String) = names.any { it in methods }
        return when {
            has("urg_sni_split") && methods.size > 1 &&
                methods.any { it != "urg_sni_split" && it !in setOf("tls_frag", "tls_record_frag") } ->
                "BYPASS_METHOD \"urg_sni_split\" can only be combined with \"tls_frag\" or \"tls_record_frag\"."
            has("sni_boundary_frag") && methods.size > 1 &&
                methods.any { it == "tls_record_frag" || it == "urg_sni_split" } ->
                "BYPASS_METHOD \"sni_boundary_frag\" cannot be combined with \"tls_record_frag\" or \"urg_sni_split\"."
            has("fake_tls") && (has("tls_record_frag") || has("urg_sni_split")) ->
                "BYPASS_METHOD \"fake_tls\" cannot be combined with \"tls_record_frag\" or \"urg_sni_split\"."
            has("ip_frag") && (has("tls_record_frag") || has("fake_tls") || has("urg_sni_split")) ->
                "BYPASS_METHOD \"ip_frag\" cannot be combined with \"tls_record_frag\", \"fake_tls\", or \"urg_sni_split\"."
            has("disorder") && (has("tls_record_frag") || has("fake_tls") || has("ip_frag") || has("urg_sni_split")) ->
                "BYPASS_METHOD \"disorder\" cannot be combined with \"tls_record_frag\", \"fake_tls\", \"ip_frag\", or \"urg_sni_split\"."
            else -> null
        }
    }

    val socketOnlyMethods = setOf("tls_frag", "ccs_prefix", "tls_padding", "mixed_case_sni", "sni_boundary_frag")

    fun displayMethodList(value: String): String =
        parseTomlStringArray(value)?.joinToString(" + ") ?: value

    private fun parseFieldText(text: String): ParsedFieldText {
        val values = ZeroDpiConfigSchema.fields.associate { it.name to it.defaultValue }.toMutableMap()
        val issues = mutableListOf<ConfigValidationIssue>()
        val seen = mutableSetOf<String>()

        text.lineSequence().forEachIndexed { lineIndex, line ->
            val trimmedLine = line.trim()
            if (trimmedLine.isEmpty() || trimmedLine.startsWith('#')) {
                return@forEachIndexed
            }
            val match = assignmentPattern.find(line)
            if (match == null) {
                val unknownKey = keyValuePattern.find(line)?.groupValues?.get(1)
                issues += ConfigValidationIssue(
                    fieldName = unknownKey,
                    message = if (unknownKey == null) {
                        "Line ${lineIndex + 1}: config.toml must use flat KEY = value assignments."
                    } else {
                        "Line ${lineIndex + 1}: unknown config field $unknownKey."
                    },
                )
                return@forEachIndexed
            }
            val fieldName = match.groupValues[1]
            val schema = ZeroDpiConfigSchema.fieldsByName[fieldName]
            if (schema == null) {
                issues += ConfigValidationIssue(
                    fieldName = fieldName,
                    message = "Line ${lineIndex + 1}: unknown config field $fieldName.",
                )
                return@forEachIndexed
            }
            val rawValue = stripInlineComment(line.substringAfter('=', missingDelimiterValue = "")).trim()

            if (!seen.add(fieldName)) {
                issues += ConfigValidationIssue(
                    fieldName = fieldName,
                    message = "$fieldName is assigned more than once; TOML requires one value per key.",
                )
            }

            val displayValue = rawTomlToDisplay(schema, rawValue)
            if (displayValue == null) {
                issues += ConfigValidationIssue(
                    fieldName = fieldName,
                    message = "Line ${lineIndex + 1}: $fieldName has invalid TOML syntax for ${schema.type.label}.",
                )
                values[fieldName] = rawValue
            } else {
                values[fieldName] = displayValue
            }
        }

        ZeroDpiConfigSchema.fields
            .filter { it.required && it.name !in seen }
            .forEach { schema ->
                issues += ConfigValidationIssue(
                    fieldName = schema.name,
                    message = "${schema.name} is required by ZeroDPI config.toml.",
                )
            }

        return ParsedFieldText(fieldText = values, issues = issues)
    }

    private fun rawTomlToDisplay(schema: ConfigFieldSchema, rawValue: String): String? =
        when (schema.type) {
            ConfigFieldType.MultiSelect -> {
                if (rawValue.trim().startsWith('[')) {
                    parseTomlStringArray(rawValue)
                        ?.let { canonicalMethodArray(it.flatMap(::expandMethodAlias)) }
                } else if (rawValue.startsWith('"')) {
                    decodeTomlString(rawValue)?.let { canonicalMethodArray(expandMethodAlias(it)) }
                } else {
                    null
                }
            }

            ConfigFieldType.Text,
            ConfigFieldType.OptionalText,
            ConfigFieldType.Enum,
            ConfigFieldType.PacketSelector,
            -> {
                if (!rawValue.startsWith('"')) {
                    null
                } else {
                    decodeTomlString(rawValue)
                }
            }

            ConfigFieldType.IntegerRange -> {
                if (rawValue.startsWith('"')) {
                    decodeTomlString(rawValue)
                } else {
                    rawValue
                }
            }

            ConfigFieldType.Boolean,
            ConfigFieldType.UInt8,
            ConfigFieldType.UInt16,
            ConfigFieldType.UInt32,
            ConfigFieldType.UInt64,
            ConfigFieldType.USize,
            ConfigFieldType.Float,
            -> rawValue
        }

    private fun parseValue(schema: ConfigFieldSchema, text: String): ParsedConfigValue =
        when (schema.type) {
            ConfigFieldType.Text,
            ConfigFieldType.OptionalText,
            -> ParsedConfigValue(TextConfigValue(text), null)

            ConfigFieldType.Enum -> {
                if (text in schema.options) {
                    ParsedConfigValue(TextConfigValue(text), null)
                } else {
                    ParsedConfigValue(null, "${schema.name} must be one of ${schema.options.joinToString()}.")
                }
            }

            ConfigFieldType.PacketSelector -> {
                val issue = validatePacketSelector(text)
                ParsedConfigValue(if (issue == null) TextConfigValue(text) else null, issue)
            }

            ConfigFieldType.IntegerRange -> {
                val issue = validateIntegerRange(text, min = Long.MIN_VALUE)
                ParsedConfigValue(if (issue == null) TextConfigValue(text) else null, issue)
            }

            ConfigFieldType.MultiSelect -> {
                val methods = parseTomlStringArray(text)
                if (methods == null) {
                    ParsedConfigValue(null, "${schema.name} must be a TOML array of method names.")
                } else {
                    val invalid = methods.filter { it !in schema.options }
                    val duplicates = methods.groupingBy { it }.eachCount().filterValues { it > 1 }.keys
                    when {
                        methods.isEmpty() ->
                            ParsedConfigValue(null, "${schema.name} must not be empty.")
                        invalid.isNotEmpty() ->
                            ParsedConfigValue(null, "${schema.name} has unknown method(s): ${invalid.joinToString()}.")
                        duplicates.isNotEmpty() ->
                            ParsedConfigValue(null, "${schema.name} has duplicate method(s): ${duplicates.joinToString()}.")
                        else -> ParsedConfigValue(TextConfigValue(canonicalMethodArray(methods)), null)
                    }
                }
            }

            ConfigFieldType.Boolean -> {
                when (text.trim().lowercase()) {
                    "true" -> ParsedConfigValue(BooleanConfigValue(true), null)
                    "false" -> ParsedConfigValue(BooleanConfigValue(false), null)
                    else -> ParsedConfigValue(null, "${schema.name} must be true or false.")
                }
            }

            ConfigFieldType.UInt8 -> parseIntegerValue(schema, text, min = 0, max = UBYTE_MAX)
            ConfigFieldType.UInt16 -> parseIntegerValue(schema, text, min = 0, max = USHORT_MAX)
            ConfigFieldType.UInt32 -> parseIntegerValue(schema, text, min = 0, max = UINT_MAX)
            ConfigFieldType.UInt64,
            ConfigFieldType.USize,
            -> parseIntegerValue(schema, text, min = 0, max = Long.MAX_VALUE)

            ConfigFieldType.Float -> {
                val value = text.trim().toDoubleOrNull()
                if (value == null || !value.isFinite()) {
                    ParsedConfigValue(null, "${schema.name} must be a finite number.")
                } else {
                    ParsedConfigValue(FloatConfigValue(value), null)
                }
            }
        }

    private fun parseIntegerValue(
        schema: ConfigFieldSchema,
        text: String,
        min: Long,
        max: Long,
    ): ParsedConfigValue {
        val value = text.trim().toLongOrNull()
        return if (value == null || value < min || value > max) {
            ParsedConfigValue(null, "${schema.name} must be an integer from $min through $max.")
        } else {
            ParsedConfigValue(IntegerConfigValue(value), null)
        }
    }

    private fun defaultValueFor(schema: ConfigFieldSchema): ConfigValue =
        parseValue(schema, schema.defaultValue).value ?: TextConfigValue(schema.defaultValue)

    private fun addRustValidationIssues(
        config: ZeroDpiConfig,
        invalidFields: Set<String>,
        issues: MutableList<ConfigValidationIssue>,
    ) {
        fun whenValid(fieldName: String, validate: () -> Unit) {
            if (fieldName !in invalidFields) {
                validate()
            }
        }

        fun requireField(fieldName: String, condition: Boolean, message: String) {
            if (!condition) {
                issues += ConfigValidationIssue(fieldName, message)
            }
        }

        if (
            "CUSTOM_DNS_ENABLED" !in invalidFields &&
            config.boolean("CUSTOM_DNS_ENABLED") &&
            "CUSTOM_DNS_SERVER" !in invalidFields
        ) {
            requireField(
                "CUSTOM_DNS_SERVER",
                isValidCustomDnsServer(config.text("CUSTOM_DNS_SERVER")),
                "CUSTOM_DNS_SERVER must be a literal IP address with an optional non-zero port.",
            )
        }
        whenValid("SCAN_TIMEOUT_SECS") {
            requireField("SCAN_TIMEOUT_SECS", config.integer("SCAN_TIMEOUT_SECS") > 0, "SCAN_TIMEOUT_SECS must be > 0.")
        }
        whenValid("BYPASS_TIMEOUT_SECS") {
            requireField("BYPASS_TIMEOUT_SECS", config.integer("BYPASS_TIMEOUT_SECS") > 0, "BYPASS_TIMEOUT_SECS must be > 0.")
        }
        whenValid("SNI_SWITCH_MIN_SCORE") {
            requireField(
                "SNI_SWITCH_MIN_SCORE",
                config.integer("SNI_SWITCH_MIN_SCORE") <= 100,
                "SNI_SWITCH_MIN_SCORE must be <= 100.",
            )
        }
        whenValid("SCAN_DOWNLOAD_CAP") {
            requireField("SCAN_DOWNLOAD_CAP", config.integer("SCAN_DOWNLOAD_CAP") > 0, "SCAN_DOWNLOAD_CAP must be > 0.")
        }
        whenValid("SCAN_UPLOAD_CAP") {
            requireField("SCAN_UPLOAD_CAP", config.integer("SCAN_UPLOAD_CAP") > 0, "SCAN_UPLOAD_CAP must be > 0.")
        }
        whenValid("SCAN_UPLOAD_PATH") {
            val path = config.text("SCAN_UPLOAD_PATH")
            requireField(
                "SCAN_UPLOAD_PATH",
                path.isNotEmpty() && path.startsWith('/') && '\r' !in path && '\n' !in path,
                "SCAN_UPLOAD_PATH must be non-empty, start with '/', and contain no CR/LF.",
            )
        }
        whenValid("SPEED_CAP_BPS") {
            val value = config.decimal("SPEED_CAP_BPS")
            requireField("SPEED_CAP_BPS", value.isFinite() && value > 0.0, "SPEED_CAP_BPS must be finite and > 0.")
        }
        whenValid("UPLOAD_SPEED_CAP_BPS") {
            val value = config.decimal("UPLOAD_SPEED_CAP_BPS")
            requireField(
                "UPLOAD_SPEED_CAP_BPS",
                value.isFinite() && value > 0.0,
                "UPLOAD_SPEED_CAP_BPS must be finite and > 0.",
            )
        }
        whenValid("SELECTED_SNI") {
            val sni = config.text("SELECTED_SNI")
            requireField(
                "SELECTED_SNI",
                sni.toByteArray(Charsets.UTF_8).size <= MAX_SNI_LEN_BYTES,
                "SELECTED_SNI must not exceed $MAX_SNI_LEN_BYTES UTF-8 bytes.",
            )
        }
        whenValid("WRONG_CHECKSUM_DELTA") {
            requireField(
                "WRONG_CHECKSUM_DELTA",
                config.integer("WRONG_CHECKSUM_DELTA") >= 1,
                "WRONG_CHECKSUM_DELTA must be >= 1.",
            )
        }
        whenValid("WRONG_ACK_OFFSET") {
            requireField("WRONG_ACK_OFFSET", config.integer("WRONG_ACK_OFFSET") >= 1, "WRONG_ACK_OFFSET must be >= 1.")
        }
        whenValid("WRONG_TIMESTAMP_OFFSET") {
            requireField(
                "WRONG_TIMESTAMP_OFFSET",
                config.integer("WRONG_TIMESTAMP_OFFSET") >= 1,
                "WRONG_TIMESTAMP_OFFSET must be >= 1.",
            )
        }
        whenValid("TLS_RECORD_FRAG_SIZE") {
            requireField(
                "TLS_RECORD_FRAG_SIZE",
                config.integer("TLS_RECORD_FRAG_SIZE") >= 1,
                "TLS_RECORD_FRAG_SIZE must be >= 1.",
            )
        }
        whenValid("TCP_SEG_SIZE") {
            val size = config.integer("TCP_SEG_SIZE")
            requireField("TCP_SEG_SIZE", size >= 1, "TCP_SEG_SIZE must be >= 1.")
            requireField("TCP_SEG_SIZE", size <= Int.MAX_VALUE, "TCP_SEG_SIZE must be <= i32::MAX.")
        }
        whenValid("TLS_FRAG_LENGTH") {
            validateIntegerRange(config.text("TLS_FRAG_LENGTH"), min = 1)?.let {
                issues += ConfigValidationIssue("TLS_FRAG_LENGTH", "TLS_FRAG_LENGTH $it")
            }
        }
        whenValid("TLS_FRAG_INTERVAL_MS") {
            validateIntegerRange(config.text("TLS_FRAG_INTERVAL_MS"), min = 0)?.let {
                issues += ConfigValidationIssue("TLS_FRAG_INTERVAL_MS", "TLS_FRAG_INTERVAL_MS $it")
            }
        }
        if ("MODE" !in invalidFields && "BYPASS_METHOD" !in invalidFields) {
            val mode = config.text("MODE")
            val methods = config.methodList("BYPASS_METHOD")
            if (mode == "ip_bypass_plus") {
                val allowed = setOf(
                    "tls_record_frag", "tls_frag", "tls_padding", "mixed_case_sni",
                    "sni_boundary_frag", "ccs_prefix", "ip_frag", "disorder",
                )
                val rejected = methods.filter { it !in allowed }
                if (rejected.isNotEmpty()) {
                    issues += ConfigValidationIssue(
                        "BYPASS_METHOD",
                        "MODE = \"ip_bypass_plus\" does not support: ${rejected.joinToString()} (real-SNI-preserving methods only).",
                    )
                }
            }
        }
        whenValid("BYPASS_METHOD") {
            validateMethodCombination(config.methodList("BYPASS_METHOD"))?.let {
                issues += ConfigValidationIssue("BYPASS_METHOD", it)
            }
        }
        whenValid("METHOD_SCAN_METHODS") {
            val methods = config.methodList("METHOD_SCAN_METHODS")
            requireField("METHOD_SCAN_METHODS", methods.isNotEmpty(), "METHOD_SCAN_METHODS must not be empty.")
        }
        whenValid("METHOD_SCAN_SAMPLES") {
            requireField("METHOD_SCAN_SAMPLES", config.integer("METHOD_SCAN_SAMPLES") >= 1, "METHOD_SCAN_SAMPLES must be >= 1.")
        }
        whenValid("METHOD_SCAN_TIMEOUT_SECS") {
            requireField("METHOD_SCAN_TIMEOUT_SECS", config.integer("METHOD_SCAN_TIMEOUT_SECS") > 0, "METHOD_SCAN_TIMEOUT_SECS must be > 0.")
        }
        whenValid("LOW_TTL_VALUE") {
            val value = config.integer("LOW_TTL_VALUE")
            requireField("LOW_TTL_VALUE", value in 1..64, "LOW_TTL_VALUE must be from 1 through 64.")
        }
        whenValid("LOW_TTL_DISCOVER_MAX") {
            val value = config.integer("LOW_TTL_DISCOVER_MAX")
            requireField("LOW_TTL_DISCOVER_MAX", value in 1..64, "LOW_TTL_DISCOVER_MAX must be from 1 through 64.")
        }
        whenValid("LOW_TTL_DISCOVER_TIMEOUT_MS") {
            requireField(
                "LOW_TTL_DISCOVER_TIMEOUT_MS",
                config.integer("LOW_TTL_DISCOVER_TIMEOUT_MS") >= 100,
                "LOW_TTL_DISCOVER_TIMEOUT_MS must be >= 100.",
            )
        }
        whenValid("IP_FRAG_SIZE") {
            val size = config.integer("IP_FRAG_SIZE")
            requireField("IP_FRAG_SIZE", size >= 8, "IP_FRAG_SIZE must be >= 8.")
            requireField("IP_FRAG_SIZE", size % 8 == 0L, "IP_FRAG_SIZE must be a multiple of 8.")
        }
        whenValid("DISORDER_SEGMENTS") {
            val segments = config.integer("DISORDER_SEGMENTS")
            requireField("DISORDER_SEGMENTS", segments == 2L || segments == 3L, "DISORDER_SEGMENTS must be 2 or 3.")
        }
        whenValid("DISORDER_DELAY_MS") {
            requireField("DISORDER_DELAY_MS", config.integer("DISORDER_DELAY_MS") <= 1000, "DISORDER_DELAY_MS must be <= 1000.")
        }
        whenValid("TLS_PADDING_SIZE") {
            validateIntegerRange(config.text("TLS_PADDING_SIZE"), min = 1)?.let {
                issues += ConfigValidationIssue("TLS_PADDING_SIZE", "TLS_PADDING_SIZE $it")
            }
            val match = integerRangePattern.matchEntire(config.text("TLS_PADDING_SIZE").trim())
            if (match != null) {
                val end = match.groupValues.getOrNull(2)?.takeIf { it.isNotBlank() }?.toLong()
                    ?: match.groupValues[1].toLong()
                requireField("TLS_PADDING_SIZE", end <= 16000, "TLS_PADDING_SIZE maximum must be <= 16000.")
            }
        }
        whenValid("TLS_PADDING_POSITION") {
            requireField(
                "TLS_PADDING_POSITION",
                config.text("TLS_PADDING_POSITION") in setOf("before", "after"),
                "TLS_PADDING_POSITION must be \"before\" or \"after\".",
            )
        }
        whenValid("CCS_PREFIX_RECORD_VERSION") {
            requireField(
                "CCS_PREFIX_RECORD_VERSION",
                Regex("""^(0x)?[0-9a-fA-F]{4}$""").matches(config.text("CCS_PREFIX_RECORD_VERSION").trim()),
                "CCS_PREFIX_RECORD_VERSION must be two hex bytes (e.g. \"0x0303\").",
            )
        }
        whenValid("SNI_SPLIT_POSITION") {
            validateSniPosition(config.text("SNI_SPLIT_POSITION"), setOf("middle", "start", "end"))?.let {
                issues += ConfigValidationIssue("SNI_SPLIT_POSITION", "SNI_SPLIT_POSITION $it")
            }
        }
        whenValid("SNI_BOUNDARY_FRAG_SPLIT_POINT") {
            validateSniPosition(config.text("SNI_BOUNDARY_FRAG_SPLIT_POINT"), setOf("extension_length", "middle"))?.let {
                issues += ConfigValidationIssue("SNI_BOUNDARY_FRAG_SPLIT_POINT", "SNI_BOUNDARY_FRAG_SPLIT_POINT $it")
            }
        }
        whenValid("SNI_BOUNDARY_FRAG_DELAY_MS") {
            validateIntegerRange(config.text("SNI_BOUNDARY_FRAG_DELAY_MS"), min = 0)?.let {
                issues += ConfigValidationIssue("SNI_BOUNDARY_FRAG_DELAY_MS", "SNI_BOUNDARY_FRAG_DELAY_MS $it")
            }
        }
        whenValid("PROXY_TEST_SNI_WEIGHT") {
            val weight = config.decimal("PROXY_TEST_SNI_WEIGHT")
            requireField(
                "PROXY_TEST_SNI_WEIGHT",
                weight in 0.0..1.0,
                "PROXY_TEST_SNI_WEIGHT must be in [0.0, 1.0].",
            )
        }
        whenValid("PROXY_TEST_TIMEOUT_SECS") {
            requireField(
                "PROXY_TEST_TIMEOUT_SECS",
                config.integer("PROXY_TEST_TIMEOUT_SECS") > 0,
                "PROXY_TEST_TIMEOUT_SECS must be > 0.",
            )
        }
        whenValid("SELECTED_IP") {
            val selectedIp = config.text("SELECTED_IP").trim()
            if (selectedIp.isNotEmpty()) {
                val ipKind = parseIpKind(selectedIp)
                if (ipKind == null) {
                    issues += ConfigValidationIssue("SELECTED_IP", "SELECTED_IP '$selectedIp' is not a valid IP address.")
                } else if (
                    "MODE" !in invalidFields &&
                    config.text("MODE") == "ip_bypass_plus" &&
                    ipKind == IpKind.Ipv6
                ) {
                    issues += ConfigValidationIssue(
                        "SELECTED_IP",
                        "MODE = \"ip_bypass_plus\" is IPv4-only; SELECTED_IP is IPv6.",
                    )
                }
            }
        }
    }

    private fun rootRequirementFor(
        config: ZeroDpiConfig,
        issues: List<ConfigValidationIssue>,
    ): RootRequirementInfo {
        if (issues.any { it.fieldName == "MODE" || it.fieldName == "BYPASS_METHOD" || it.fieldName == "METHOD_SCAN_METHODS" }) {
            return RootRequirementInfo(
                requiresRoot = false,
                message = "Fix MODE and bypass-method fields before root impact can be determined.",
                alternatives = emptyList(),
            )
        }

        val mode = config.text("MODE")
        val methods = if (mode in ZeroDpiConfigSchema.methodScanModes) {
            config.methodList("METHOD_SCAN_METHODS")
        } else {
            config.methodList("BYPASS_METHOD")
        }
        val requiresRoot = requiresPacketInterception(mode, methods.toSet())

        return if (requiresRoot) {
            RootRequirementInfo(
                requiresRoot = true,
                message = "MODE = \"$mode\" with method(s) ${methods.joinToString(" + ")} uses Android/Linux packet interception and will require root through su.",
                alternatives = listOf(
                    "MODE = \"ip_bypass\"",
                    "MODE = \"sni_scan\"",
                    "MODE = \"ip_scan\"",
                    "Socket-only methods only: tls_frag, ccs_prefix, tls_padding, mixed_case_sni, sni_boundary_frag",
                ),
            )
        } else {
            RootRequirementInfo(
                requiresRoot = false,
                message = "This MODE/method combination is rootless for the Android app.",
                alternatives = emptyList(),
            )
        }
    }

    private fun validatePacketSelector(value: String): String? {
        val trimmed = value.trim()
        if (trimmed == "tlshello") {
            return null
        }
        val match = packetRangePattern.matchEntire(trimmed)
            ?: return "must be tlshello, a 1-based index, or a 1-based range."
        val start = match.groupValues[1].toLong()
        val end = match.groupValues.getOrNull(2)?.takeIf { it.isNotBlank() }?.toLong() ?: start
        return when {
            start < 1 -> "range start must be >= 1."
            end < start -> "range end must not be lower than start."
            else -> null
        }
    }

    private fun validateIntegerRange(value: String, min: Long): String? {
        val match = integerRangePattern.matchEntire(value.trim())
            ?: return "must be an integer or inclusive range."
        val start = match.groupValues[1].toLong()
        val end = match.groupValues.getOrNull(2)?.takeIf { it.isNotBlank() }?.toLong() ?: start
        return when {
            start < min -> "minimum must be >= $min."
            end < start -> "range end must not be lower than start."
            else -> null
        }
    }

    private fun toTomlLiteral(schema: ConfigFieldSchema, value: String): String =
        when (schema.type) {
            ConfigFieldType.MultiSelect -> value.trim()

            ConfigFieldType.Text,
            ConfigFieldType.OptionalText,
            ConfigFieldType.Enum,
            ConfigFieldType.PacketSelector,
            -> "\"${escapeTomlString(value)}\""

            ConfigFieldType.IntegerRange -> {
                if (value.trim().matches(Regex("""-?\d+"""))) {
                    value.trim()
                } else {
                    "\"${escapeTomlString(value)}\""
                }
            }

            ConfigFieldType.Boolean,
            ConfigFieldType.UInt8,
            ConfigFieldType.UInt16,
            ConfigFieldType.UInt32,
            ConfigFieldType.UInt64,
            ConfigFieldType.USize,
            ConfigFieldType.Float,
            -> value.trim().ifEmpty { "\"\"" }
        }

    private fun stripInlineComment(raw: String): String {
        var inString = false
        var escaping = false
        raw.forEachIndexed { index, char ->
            if (escaping) {
                escaping = false
                return@forEachIndexed
            }
            when (char) {
                '\\' -> if (inString) escaping = true
                '"' -> inString = !inString
                '#' -> if (!inString) return raw.substring(0, index).trimEnd()
            }
        }
        return raw.trimEnd()
    }

    private fun trailingComment(raw: String): String =
        raw.dropWhile { it.isWhitespace() }
            .let { stripped ->
                val commentStart = findUnquotedCommentIndex(stripped)
                if (commentStart >= 0) stripped.substring(commentStart).trim() else ""
            }

    private fun findUnquotedCommentIndex(raw: String): Int {
        var inString = false
        var escaping = false
        raw.forEachIndexed { index, char ->
            if (escaping) {
                escaping = false
                return@forEachIndexed
            }
            when (char) {
                '\\' -> if (inString) escaping = true
                '"' -> inString = !inString
                '#' -> if (!inString) return index
            }
        }
        return -1
    }

    private fun decodeTomlString(raw: String): String? {
        if (!raw.startsWith('"')) {
            return null
        }
        val builder = StringBuilder()
        var index = 1
        while (index < raw.length) {
            val char = raw[index]
            when {
                char == '"' -> {
                    val trailing = raw.substring(index + 1).trim()
                    return if (trailing.isEmpty()) builder.toString() else null
                }

                char == '\\' -> {
                    index += 1
                    if (index >= raw.length) {
                        return null
                    }
                    builder.append(
                        when (raw[index]) {
                            '"' -> '"'
                            '\\' -> '\\'
                            'n' -> '\n'
                            'r' -> '\r'
                            't' -> '\t'
                            else -> return null
                        },
                    )
                }

                else -> builder.append(char)
            }
            index += 1
        }
        return null
    }

    private fun escapeTomlString(value: String): String =
        buildString {
            value.forEach { char ->
                append(
                    when (char) {
                        '\\' -> "\\\\"
                        '"' -> "\\\""
                        '\n' -> "\\n"
                        '\r' -> "\\r"
                        '\t' -> "\\t"
                        else -> char.toString()
                    },
                )
            }
        }

    private fun parseIpKind(value: String): IpKind? =
        when {
            isValidIpv4(value) -> IpKind.Ipv4
            isLikelyIpv6Literal(value) -> {
                val address = runCatching { InetAddress.getByName(value) }.getOrNull()
                if (address is Inet6Address) IpKind.Ipv6 else null
            }
            else -> null
        }

    private fun isValidCustomDnsServer(rawValue: String): Boolean {
        val value = rawValue.trim()
        if (value.isEmpty()) return false

        if (value.startsWith('[')) {
            val closeBracket = value.indexOf(']')
            if (closeBracket <= 1 || closeBracket == value.lastIndex) return false
            val ip = value.substring(1, closeBracket)
            val portText = value.substring(closeBracket + 1)
            val port = portText.drop(1).toIntOrNull()
            return portText.startsWith(':') &&
                port != null &&
                port in 1..65535 &&
                parseIpKind(ip) == IpKind.Ipv6
        }

        if (parseIpKind(value) != null) return true

        val colonIndex = value.lastIndexOf(':')
        if (colonIndex <= 0 || value.indexOf(':') != colonIndex) return false
        val ip = value.substring(0, colonIndex)
        val port = value.substring(colonIndex + 1).toIntOrNull()
        return parseIpKind(ip) == IpKind.Ipv4 && port != null && port in 1..65535
    }

    private fun isValidIpv4(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) {
            return false
        }
        return parts.all { part ->
            part.isNotEmpty() &&
                part.all { it.isDigit() } &&
                part.toIntOrNull()?.let { it in 0..255 } == true
        }
    }

    private fun isLikelyIpv6Literal(value: String): Boolean =
        ':' in value && value.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }

    private data class ParsedFieldText(
        val fieldText: Map<String, String>,
        val issues: List<ConfigValidationIssue>,
    )

    private data class ParsedConfigValue(
        val value: ConfigValue?,
        val issue: String?,
    )

    private enum class IpKind {
        Ipv4,
        Ipv6,
    }

    private const val UBYTE_MAX = 255L
    private const val USHORT_MAX = 65_535L
    private const val UINT_MAX = 4_294_967_295L
}
