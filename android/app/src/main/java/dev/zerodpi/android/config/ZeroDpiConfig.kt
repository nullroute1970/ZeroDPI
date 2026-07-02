package dev.zerodpi.android.config

import java.net.Inet6Address
import java.net.InetAddress

enum class ConfigSection(val title: String) {
    ProxyListener("Proxy listener"),
    OperatingMode("Operating mode"),
    InputFiles("Input files"),
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

object ZeroDpiConfigSchema {
    val modeOptions = listOf(
        "sni_spoof",
        "ip_bypass",
        "ip_bypass_plus",
        "sni_scan",
        "ip_scan",
        "proxy_scan",
    )

    val bypassMethodOptions = listOf(
        "wrong_seq",
        "wrong_checksum",
        "wrong_md5",
        "wrong_seq_wrong_md5",
        "wrong_ack",
        "wrong_timestamp",
        "tls_record_frag",
        "wrong_seq_tls_frag",
        "wrong_md5_tls_frag",
        "wrong_seq_tls_record_frag",
        "tls_frag",
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
            type = ConfigFieldType.Enum,
            defaultValue = "wrong_seq_tls_frag",
            section = ConfigSection.BypassEngine,
            validationRule = "Must be one of the supported bypass method strings.",
            rootImpact = ConfigRootImpact.ControlsRootRequirement,
            helpText = "Bypass engine used by SNI and proxy modes.",
            options = bypassMethodOptions,
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

    fun requiresPacketInterception(mode: String, bypassMethod: String): Boolean =
        mode in setOf("sni_spoof", "proxy_scan", "ip_bypass_plus") && bypassMethod != "tls_frag"

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
            val bypassMethod = config.text("BYPASS_METHOD")
            if (mode == "ip_bypass_plus" && bypassMethod !in setOf("tls_record_frag", "tls_frag")) {
                issues += ConfigValidationIssue(
                    "BYPASS_METHOD",
                    "MODE = \"ip_bypass_plus\" supports only \"tls_record_frag\" or \"tls_frag\".",
                )
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
        if (issues.any { it.fieldName == "MODE" || it.fieldName == "BYPASS_METHOD" }) {
            return RootRequirementInfo(
                requiresRoot = false,
                message = "Fix MODE and BYPASS_METHOD before root impact can be determined.",
                alternatives = emptyList(),
            )
        }

        val mode = config.text("MODE")
        val bypassMethod = config.text("BYPASS_METHOD")
        val requiresRoot = requiresPacketInterception(mode, bypassMethod)

        return if (requiresRoot) {
            RootRequirementInfo(
                requiresRoot = true,
                message = "MODE = \"$mode\" with BYPASS_METHOD = \"$bypassMethod\" uses Android/Linux packet interception and will require root through su.",
                alternatives = listOf(
                    "MODE = \"ip_bypass\"",
                    "MODE = \"sni_scan\"",
                    "MODE = \"ip_scan\"",
                    "BYPASS_METHOD = \"tls_frag\" where the selected mode supports it",
                ),
            )
        } else {
            RootRequirementInfo(
                requiresRoot = false,
                message = "This MODE/BYPASS_METHOD combination is rootless for the Android app.",
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
