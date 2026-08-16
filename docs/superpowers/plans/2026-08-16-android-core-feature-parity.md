# Android Core Feature Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose every bypass method, operating mode, and config parameter that zerodpi-core supports in the Android app's Kotlin config schema, Configure-screen GUI, and a new Home-tab method-scan results card.

**Architecture:** The Android app ships the same Rust binary (via `jniLibs/libzerodpi_exec.so`, built by `build.py`), so **no Rust changes are needed** — the binary already implements every feature. All work is in the Kotlin app: (1) extend the flat-TOML config schema/parser (`ZeroDpiConfig.kt`) with a new MultiSelect field type for TOML arrays (`BYPASS_METHOD`, `METHOD_SCAN_METHODS`), 31 new fields, core-mirroring validation and root-requirement logic; (2) add the matching GUI controls; (3) update the bundled `assets/zerodpi/config.toml`; (4) add a method-scan results card on the Home tab driven by runtime events + the `METHOD_SCAN_OUTPUT` JSON report parsed with the app's existing kotlinx-serialization dependency.

**Tech Stack:** Kotlin, Jetpack Compose (Material 3), StateFlow, kotlinx-serialization-json 1.11.0 (already a dependency of `android/app`), JUnit4 unit tests, Compose androidTest. Rust workspace untouched (only rebuilt via `build.py` for packaging).

**Spec:** Design approved in chat on 2026-08-16 (scope: all 10 missing features; multi-select BYPASS_METHOD; dedicated method-scan results view as a Home-tab card shown only when MODE is a method-scan mode). Summary embedded below; no separate spec file.

## Design Summary (approved in chat)

1. **Config schema** — new modes `sni_method_scan`/`ip_method_scan`; `BYPASS_METHOD` and `METHOD_SCAN_METHODS` become multi-select TOML arrays (legacy single-string values and combo aliases still parse, expanding at parse time); 31 new fields in 10 new sections; validation and root-requirement logic mirror core `config.rs` exactly (socket-only method set is rootless; combo restrictions enforced).
2. **GUI** — checkbox-list control for the two multi-select fields; new sections render automatically in the Configure screen's Advanced view.
3. **Method-scan results** — card on Home tab visible only when MODE ∈ {`sni_method_scan`, `ip_method_scan`}: idle prompt → live progress (runtime `scan_progress` events, phase `method_test`) → ranked results table parsed from the auto-filled `METHOD_SCAN_OUTPUT` JSON; errors surface inline; cleared on config change.
4. **Assets & tests** — bundled `config.toml` updated to mirror repo `config.toml`; unit + UI tests for all of the above; `SupportBundle` redacts `METHOD_SCAN_OUTPUT`.

## Global Constraints

Exact values copied from `crates/zerodpi-core/src/config.rs` (single source of truth). Every task's requirements implicitly include this section.

- **Valid MODE values:** `"sni_spoof"`, `"ip_bypass"`, `"ip_bypass_plus"`, `"sni_scan"`, `"ip_scan"`, `"proxy_scan"`, `"sni_method_scan"`, `"ip_method_scan"`.
- **Base bypass methods (16, in this order):** `"wrong_seq"`, `"wrong_ack"`, `"wrong_checksum"`, `"wrong_md5"`, `"wrong_timestamp"`, `"low_ttl"`, `"tls_record_frag"`, `"fake_tls"`, `"ip_frag"`, `"disorder"`, `"tls_frag"`, `"ccs_prefix"`, `"tls_padding"`, `"mixed_case_sni"`, `"urg_sni_split"`, `"sni_boundary_frag"`.
- **Combo aliases (legacy input, expanded at parse time):** `"wrong_seq_wrong_md5"` → `[wrong_seq, wrong_md5]`; `"wrong_seq_tls_frag"` → `[wrong_seq, tls_frag]`; `"wrong_md5_tls_frag"` → `[wrong_md5, tls_frag]`; `"wrong_seq_tls_record_frag"` → `[wrong_seq, tls_record_frag]`.
- **Socket-only (rootless) methods:** `"tls_frag"`, `"ccs_prefix"`, `"tls_padding"`, `"mixed_case_sni"`, `"sni_boundary_frag"`. Everything else requires the packet interceptor (root on Android).
- **Combo rules (BYPASS_METHOD):** `urg_sni_split` only combinable with `tls_frag`/`tls_record_frag`; `sni_boundary_frag` not combinable with `tls_record_frag`/`urg_sni_split`; `fake_tls` not combinable with `tls_record_frag`/`urg_sni_split`; `ip_frag` not combinable with `tls_record_frag`/`fake_tls`/`urg_sni_split`; `disorder` not combinable with `tls_record_frag`/`fake_tls`/`ip_frag`/`urg_sni_split`; list must be non-empty, no duplicates, all entries valid base methods.
- **ip_bypass_plus allowed methods (real-SNI-preserving only):** `tls_record_frag`, `tls_frag`, `tls_padding`, `mixed_case_sni`, `sni_boundary_frag`, `ccs_prefix`, `ip_frag`, `disorder`.
- **Defaults:** `BYPASS_METHOD` = `["wrong_seq", "tls_frag"]`; `METHOD_SCAN_METHODS` = all 16 base methods; `METHOD_SCAN_SAMPLES` = 3 (must be ≥ 1); `METHOD_SCAN_INTERVAL_MS` = 1000; `METHOD_SCAN_TIMEOUT_SECS` = 10 (must be > 0); `METHOD_SCAN_OUTPUT` = `""`; `LOW_TTL_VALUE` = 5 (1..=64); `LOW_TTL_DISCOVER_MAX` = 32 (1..=64); `LOW_TTL_DISCOVER_TIMEOUT_MS` = 5000 (≥ 100); `FAKE_TLS_EXTRA_OFFSET` = 0; `IP_FRAG_SIZE` = 24 (≥ 8, multiple of 8); `IP_FRAG_ONLY_FIRST_PACKET` = true; `DISORDER_SEGMENTS` = 2 (2 or 3); `DISORDER_DELAY_MS` = 0 (≤ 1000); `DISORDER_REVERSE` = true; `DISORDER_ONLY_FIRST_PACKET` = true; `SNI_SPLIT_DUMMY_BYTE` = 0; `SNI_SPLIT_POSITION` = `"middle"`; `SNI_BOUNDARY_FRAG_SPLIT_POINT` = `"extension_length"`; `SNI_BOUNDARY_FRAG_DELAY_MS` = `"5-10"` (min ≥ 0); `TLS_PADDING_SIZE` = `"1500-2500"` (min ≥ 1, max ≤ 16000); `TLS_PADDING_POSITION` = `"before"`; `MIXED_CASE_SNI_FLIP_ALL` = false; `CCS_PREFIX_RECORD_VERSION` = `"0x0303"` (hex, 2 bytes, `0x` prefix optional). All `*_SET_PSH`, `*_BUMP_IP_IDENT`, `*_COMPLETE_IMMEDIATELY`, and `FAKE_TLS_FORWARD_REAL` defaults = true. `LOW_TTL_DISCOVER` default = false.
- **Position validators:** `SNI_SPLIT_POSITION` ∈ {`"middle"`, `"start"`, `"end"`} or a non-negative integer string. `SNI_BOUNDARY_FRAG_SPLIT_POINT` ∈ {`"extension_length"`, `"middle"`} or a non-negative integer string.
- **Existing test invariant:** `ZeroDpiConfigSchemaTest.schemaFieldsMatchRustConfigFields` asserts the Android field-name set equals the 99 `pub FIELD:` names in the Rust `Config` struct — it currently FAILS (schema is stale) and must pass from Task 2 onward.
- **No new Gradle dependencies.** Use kotlinx-serialization-json (already present) for the report JSON.
- **Kotlin style:** 4-space indentation, `internal` visibility for UI composables, strings in `res/values/strings.xml`, testTags on interactive controls.
- **No Rust source changes.** Do not edit anything under `crates/` or `windivert/`.

---

### Task 1: MultiSelect field type + TOML array parsing

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/config/ZeroDpiConfig.kt` (enum entry, accessor, display/parse/format branches)
- Test: `android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt` (add tests; do not touch existing ones yet)

**Interfaces:**
- Consumes: existing `ConfigFieldType`, `ZeroDpiConfigToml` structure.
- Produces (used by Tasks 2–4, 8, 9):
  - `ConfigFieldType.MultiSelect`
  - `internal fun parseTomlStringArray(raw: String): List<String>?` — top-level in `ZeroDpiConfig.kt`, null unless the whole string is a valid TOML array of quoted strings.
  - `internal fun expandMethodAlias(name: String): List<String>`
  - `internal fun canonicalMethodArray(methods: List<String>): String` — returns `["a", "b"]`.
  - `ZeroDpiConfig.methodList(name: String): List<String>`
  - `ZeroDpiConfigToml.displayMethodList(value: String): String` — joins with `" + "` for labels.

- [ ] **Step 1: Write the failing tests**

Append to `ZeroDpiConfigSchemaTest.kt` (no new fields exist yet, so these tests reference `parseTomlStringArray`/`expandMethodAlias` directly and the parser branch via a config that only uses existing fields):

```kotlin
    @Test
    fun parsesTomlStringArrays() {
        assertEquals(listOf("wrong_seq", "tls_frag"), parseTomlStringArray("""["wrong_seq", "tls_frag"]"""))
        assertEquals(listOf("a\"b"), parseTomlStringArray("""["a\"b"]"""))
        assertNull(parseTomlStringArray("""["wrong_seq" "tls_frag"]"""))
        assertNull(parseTomlStringArray("""wrong_seq"""))
        assertNull(parseTomlStringArray("""["a", "b",]""")) // trailing comma invalid
        assertNull(parseTomlStringArray("""["unterminated]"""))
    }

    @Test
    fun expandsComboAliases() {
        assertEquals(listOf("wrong_seq", "wrong_md5"), expandMethodAlias("wrong_seq_wrong_md5"))
        assertEquals(listOf("tls_frag"), expandMethodAlias("tls_frag"))
    }

    @Test
    fun methodListAccessorReadsCanonicalArray() {
        val state = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_spoof"
            BYPASS_METHOD = ["wrong_seq", "tls_frag"]
            """.trimIndent(),
        )
        assertEquals(listOf("wrong_seq", "tls_frag"), state.config.methodList("BYPASS_METHOD"))
        assertTrue(state.canStart)
    }
```

(Imports needed at top of test file: `assertEquals`, `assertNull` from `org.junit.Assert`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: compilation FAILS — `parseTomlStringArray`, `expandMethodAlias` unresolved (schema test already passing tests unaffected).

- [ ] **Step 3: Implement**

In `ZeroDpiConfig.kt`, add to the `ConfigFieldType` enum:

```kotlin
    MultiSelect("method list"),
```

Add top-level helpers (file scope, after the imports/classes — put them right before `object ZeroDpiConfigSchema`):

```kotlin
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
    }
    return items
}
```

In `ZeroDpiConfig` add the accessor next to `text()`:

```kotlin
    fun methodList(name: String): List<String> =
        parseTomlStringArray(text(name)) ?: emptyList()
```

In `ZeroDpiConfigToml`, extend `rawTomlToDisplay` — add a branch before the `Text/...` branch:

```kotlin
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
```

Extend `parseValue` with a `MultiSelect` branch (before `Boolean`):

```kotlin
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
```

Extend `toTomlLiteral` with the `MultiSelect` branch (return the value unchanged — it is already canonical TOML):

```kotlin
            ConfigFieldType.MultiSelect -> value.trim()
```

Add `displayMethodList` to `ZeroDpiConfigToml`:

```kotlin
    fun displayMethodList(value: String): String =
        parseTomlStringArray(value)?.joinToString(" + ") ?: value
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: PASS (new tests green; pre-existing tests still green — note `schemaFieldsMatchRustConfigFields` is still failing at this point, that is expected and fixed in Task 2; run with `--tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"` scoping and confirm only that test's assertion fails).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/config/ZeroDpiConfig.kt android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt
git commit -m "feat(android): add MultiSelect config type with TOML array parsing"
```

---

### Task 2: New sections, modes, and all 31 field schemas

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/config/ZeroDpiConfig.kt`
- Test: `android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt`

**Interfaces:**
- Consumes: `ConfigFieldType.MultiSelect`, `canonicalMethodArray` (Task 1).
- Produces (used by Tasks 3–5, 8, 9):
  - `ZeroDpiConfigSchema.baseBypassMethods: List<String>` (16 entries, order fixed per Global Constraints).
  - `ZeroDpiConfigSchema.methodScanModes: Set<String>` = `setOf("sni_method_scan", "ip_method_scan")`.
  - 10 new `ConfigSection` entries: `MethodScan`, `LowTtl`, `FakeTls`, `IpFrag`, `Disorder`, `UrgSniSplit`, `SniBoundaryFrag`, `TlsPadding`, `MixedCaseSni`, `CcsPrefix`.

- [ ] **Step 1: Write the failing test**

Append to `ZeroDpiConfigSchemaTest.kt`:

```kotlin
    @Test
    fun schemaCoversEveryRustConfigField() {
        // existing schemaFieldsMatchRustConfigFields already asserts exact equality;
        // this duplicates it so the two new-field tasks have a scoped gate.
        val rustConfig = findRepoFile("crates/zerodpi-core/src/config.rs")
        val configBody = Regex("""(?s)pub struct Config\s*\{(.*?)\n\}""")
            .find(rustConfig.readText())!!.groupValues[1]
        val rustFields = Regex("""(?m)^\s+pub\s+([A-Z0-9_]+):""")
            .findAll(configBody).map { it.groupValues[1] }.toSet()
        val androidFields = ZeroDpiConfigSchema.fields.map { it.name }.toSet()
        val missing = rustFields - androidFields
        assertTrue("Android schema missing Rust fields: ${missing.sorted()}", missing.isEmpty())
    }

    @Test
    fun methodScanDefaultsMatchCore() {
        val state = ZeroDpiConfigToml.analyze("")
        assertEquals(16, state.config.methodList("METHOD_SCAN_METHODS").size)
        assertEquals("3", state.valueFor("METHOD_SCAN_SAMPLES"))
        assertEquals("1000", state.valueFor("METHOD_SCAN_INTERVAL_MS"))
        assertEquals("10", state.valueFor("METHOD_SCAN_TIMEOUT_SECS"))
        assertEquals("", state.valueFor("METHOD_SCAN_OUTPUT"))
        assertEquals("0x0303", state.valueFor("CCS_PREFIX_RECORD_VERSION"))
        assertEquals("5", state.valueFor("LOW_TTL_VALUE"))
        assertEquals("5000", state.valueFor("LOW_TTL_DISCOVER_TIMEOUT_MS"))
        assertEquals("24", state.valueFor("IP_FRAG_SIZE"))
        assertEquals("2", state.valueFor("DISORDER_SEGMENTS"))
        assertEquals("middle", state.valueFor("SNI_SPLIT_POSITION"))
        assertEquals("extension_length", state.valueFor("SNI_BOUNDARY_FRAG_SPLIT_POINT"))
        assertEquals("5-10", state.valueFor("SNI_BOUNDARY_FRAG_DELAY_MS"))
        assertEquals("1500-2500", state.valueFor("TLS_PADDING_SIZE"))
        assertEquals("before", state.valueFor("TLS_PADDING_POSITION"))
        assertEquals("false", state.valueFor("MIXED_CASE_SNI_FLIP_ALL"))
        assertTrue(ZeroDpiConfigSchema.methodScanModes.contains("sni_method_scan"))
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: `schemaCoversEveryRustConfigField` FAILS listing 31 missing fields; `methodScanDefaultsMatchCore` FAILS (fields absent → defaults empty).

- [ ] **Step 3: Implement enum entries and option lists**

In `ConfigSection` add after `WrongTimestamp`:

```kotlin
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
```

In `ZeroDpiConfigSchema`, extend `modeOptions`:

```kotlin
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
```

Replace `bypassMethodOptions` with:

```kotlin
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
```

- [ ] **Step 4: Change BYPASS_METHOD field and add the 31 new field entries**

In `fields`, replace the existing `BYPASS_METHOD` entry:

```kotlin
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
```

Append the following 31 entries at the end of the `fields` list (before the closing `)` of `listOf`):

```kotlin
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: PASS — `schemaCoversEveryRustConfigField`, `schemaFieldsMatchRustConfigFields`, and `methodScanDefaultsMatchCore` all green.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/config/ZeroDpiConfig.kt android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt
git commit -m "feat(android): add method-scan, low_ttl, fake_tls, ip_frag, disorder, and socket-side config schemas"
```

---

### Task 3: Cross-field validation + root-requirement logic

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/config/ZeroDpiConfig.kt` (`addRustValidationIssues`, `rootRequirementFor`, `requiresPacketInterception`)
- Test: `android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt` (update `rootRequirementMatchesAndroidMatrix`, add combo/position tests)

**Interfaces:**
- Consumes: `ZeroDpiConfig.methodList`, `ConfigSection` fields from Task 2; `validateIntegerRange` (existing private helper).
- Produces (used by Tasks 4, 8, 9):
  - `internal fun validateMethodCombination(methods: List<String>): String?`
  - `internal fun validateSniPosition(value: String, allowedWords: Set<String>): String?` — null if `value` is one of `allowedWords` or a non-negative integer.
  - `ZeroDpiConfigToml.requiresPacketInterception(mode: String, bypassMethods: Set<String>): Boolean` — NEW SIGNATURE (was `(String, String)`).
  - `ZeroDpiConfigToml.socketOnlyMethods: Set<String>` (public val on the object).

- [ ] **Step 1: Write the failing tests**

Append to `ZeroDpiConfigSchemaTest.kt`:

```kotlin
    @Test
    fun rejectsDisorderCombinedWithIpFrag() {
        val state = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_spoof"
            BYPASS_METHOD = ["disorder", "ip_frag"]
            """.trimIndent(),
        )
        assertFalse(state.canStart)
        assertTrue(state.issues.any { it.fieldName == "BYPASS_METHOD" && "disorder" in it.message })
    }

    @Test
    fun acceptsCcsPrefixCombinedWithWrongSeq() {
        val state = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_spoof"
            BYPASS_METHOD = ["wrong_seq", "ccs_prefix"]
            """.trimIndent(),
        )
        assertTrue("Unexpected issues: ${state.issues}", state.canStart)
    }

    @Test
    fun enforcesIpBypassPlusMethodAllowlist() {
        val state = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "ip_bypass_plus"
            BYPASS_METHOD = ["wrong_seq"]
            """.trimIndent(),
        )
        assertFalse(state.canStart)
        assertTrue(state.issues.any { it.fieldName == "BYPASS_METHOD" && "ip_bypass_plus" in it.message })
    }

    @Test
    fun validatesNewMethodParameters() {
        fun issuesFor(config: String) = ZeroDpiConfigToml.analyze(config).issues.map { it.fieldName }
        fun base(method: String) = """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_spoof"
            BYPASS_METHOD = ["$method"]
            """.trimIndent()
        assertTrue("IP_FRAG_SIZE" in issuesFor(base("ip_frag") + "IP_FRAG_SIZE = 26\n"))
        assertTrue("DISORDER_SEGMENTS" in issuesFor(base("disorder") + "DISORDER_SEGMENTS = 4\n"))
        assertTrue("DISORDER_DELAY_MS" in issuesFor(base("disorder") + "DISORDER_DELAY_MS = 2000\n"))
        assertTrue("LOW_TTL_VALUE" in issuesFor(base("low_ttl") + "LOW_TTL_VALUE = 0\n"))
        assertTrue("LOW_TTL_DISCOVER_TIMEOUT_MS" in issuesFor(base("low_ttl") + "LOW_TTL_DISCOVER_TIMEOUT_MS = 50\n"))
        assertTrue("TLS_PADDING_SIZE" in issuesFor(base("tls_padding") + "TLS_PADDING_SIZE = \"20000-30000\"\n"))
        assertTrue("TLS_PADDING_POSITION" in issuesFor(base("tls_padding") + "TLS_PADDING_POSITION = \"sideways\"\n"))
        assertTrue("CCS_PREFIX_RECORD_VERSION" in issuesFor(base("ccs_prefix") + "CCS_PREFIX_RECORD_VERSION = \"0x03\"\n"))
        assertTrue("SNI_SPLIT_POSITION" in issuesFor(base("urg_sni_split") + "SNI_SPLIT_POSITION = \"nope\"\n"))
        assertTrue("SNI_BOUNDARY_FRAG_SPLIT_POINT" in issuesFor(base("sni_boundary_frag") + "SNI_BOUNDARY_FRAG_SPLIT_POINT = \"nope\"\n"))
        assertTrue("SNI_BOUNDARY_FRAG_DELAY_MS" in issuesFor(base("sni_boundary_frag") + "SNI_BOUNDARY_FRAG_DELAY_MS = \"-5-10\"\n"))
        assertTrue("METHOD_SCAN_SAMPLES" in issuesFor(base("wrong_seq") + "METHOD_SCAN_SAMPLES = 0\n"))
        assertTrue("METHOD_SCAN_TIMEOUT_SECS" in issuesFor(base("wrong_seq") + "METHOD_SCAN_TIMEOUT_SECS = 0\n"))
        assertTrue("METHOD_SCAN_METHODS" in issuesFor(base("wrong_seq") + "METHOD_SCAN_METHODS = [\"bogus\"]\n"))
    }

    @Test
    fun validatesSniPositions() {
        assertNull(validateSniPosition("middle", setOf("middle", "start", "end")))
        assertNull(validateSniPosition("12", setOf("extension_length", "middle")))
        assertNull(validateSniPosition("0", setOf("extension_length", "middle")))
        assertNotNull(validateSniPosition("nope", setOf("middle", "start", "end")))
        assertNotNull(validateSniPosition("-1", setOf("middle", "start", "end")))
    }
```

Replace the existing `rootRequirementMatchesAndroidMatrix` test with the new signature:

```kotlin
    @Test
    fun rootRequirementMatchesAndroidMatrix() {
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("wrong_seq")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("tls_frag")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("ccs_prefix")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("tls_frag", "ccs_prefix")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("wrong_seq", "ccs_prefix")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass", setOf("wrong_seq")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass_plus", setOf("tls_record_frag")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass_plus", setOf("tls_frag")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass_plus", setOf("disorder")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_scan", setOf("wrong_seq")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_scan", setOf("wrong_seq")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("proxy_scan", setOf("wrong_seq")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("proxy_scan", setOf("tls_frag")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("sni_method_scan", setOf("wrong_seq")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_method_scan", setOf("tls_frag", "ccs_prefix")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_method_scan", setOf("tls_padding")))
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: compilation FAILS — `validateSniPosition` unresolved and `requiresPacketInterception` called with `Set<String>` but declared `(String, String)`.

- [ ] **Step 3: Implement validators and combo rules**

Add top-level helper (next to the Task 1 helpers):

```kotlin
internal fun validateSniPosition(value: String, allowedWords: Set<String>): String? {
    val trimmed = value.trim()
    return when {
        trimmed in allowedWords -> null
        trimmed.toLongOrNull()?.let { it >= 0 } == true -> null
        else -> "must be one of ${allowedWords.joinToString()} or a non-negative index."
    }
}
```

Add to `ZeroDpiConfigToml` (as a companion-free internal function on the object):

```kotlin
    val socketOnlyMethods = setOf("tls_frag", "ccs_prefix", "tls_padding", "mixed_case_sni", "sni_boundary_frag")

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

    fun requiresPacketInterception(mode: String, bypassMethods: Set<String>): Boolean {
        val needsInterceptor = bypassMethods.any { it !in socketOnlyMethods }
        return when (mode) {
            "sni_spoof", "proxy_scan", "ip_bypass_plus", "sni_method_scan", "ip_method_scan" -> needsInterceptor
            else -> false
        }
    }
```

In `addRustValidationIssues`, append these validations (inside the function, after the existing `PROXY_TEST_*` blocks):

```kotlin
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
```

Replace the existing `ip_bypass_plus` block (the one comparing `bypassMethod !in setOf("tls_record_frag", "tls_frag")`) with:

```kotlin
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
```

Rewrite `rootRequirementFor` to use the mode-appropriate method list and update the alternatives:

```kotlin
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: PASS for all tests in the class.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/config/ZeroDpiConfig.kt android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt
git commit -m "feat(android): mirror core combo validation and rootless method matrix"
```

---

### Task 4: Multi-select GUI control

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/UiComponents.kt` (new branch + new composable)
- Test: `android/app/src/androidTest/java/dev/zerodpi/android/ui/MethodSelectControlTest.kt` (create)

**Interfaces:**
- Consumes: `ConfigFieldType.MultiSelect` (Task 1), `parseTomlStringArray`, `canonicalMethodArray`, field schemas (Task 2).
- Produces: `MethodSelectControl` rendered by `ConfigFieldControl` for `BYPASS_METHOD`/`METHOD_SCAN_METHODS`; testTags `method_select_<method>` per row.

- [ ] **Step 1: Write the failing UI test**

Create `android/app/src/androidTest/java/dev/zerodpi/android/ui/MethodSelectControlTest.kt`:

```kotlin
package dev.zerodpi.android.ui

import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import dev.zerodpi.android.config.ConfigFieldSchema
import dev.zerodpi.android.config.ConfigFieldType
import dev.zerodpi.android.config.ConfigSection
import dev.zerodpi.android.config.ConfigEditorState
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
```

Note: `ConfigEditorState` is in `dev.zerodpi.android.config` and its constructor takes `(config, fieldText, issues, rootRequirement)` — field names are public data-class params.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest --tests "dev.zerodpi.android.ui.MethodSelectControlTest"` (emulator/device required)
Expected: FAIL — `ConfigFieldType.MultiSelect` falls into the default `OutlinedTextField` branch; nodes with tag `method_select_wrong_seq` do not exist.

- [ ] **Step 3: Implement the control**

In `UiComponents.kt`, extend the `when (field.type)` in `ConfigFieldControl` with a new branch before the `else`:

```kotlin
            ConfigFieldType.MultiSelect -> MethodSelectControl(
                field = field,
                value = value,
                enabled = enabled,
                onChanged = onChanged,
            )
```

Add the composable at file scope (private, above `RuntimeStatus.isTransient`), plus imports `parseTomlStringArray`/`canonicalMethodArray` from `dev.zerodpi.android.config`:

```kotlin
@Composable
private fun MethodSelectControl(
    field: ConfigFieldSchema,
    value: String,
    enabled: Boolean,
    onChanged: (String, String) -> Unit,
) {
    val selected = remember(value) { parseTomlStringArray(value).orEmpty().toSet() }
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        field.options.forEach { option ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = option,
                    modifier = Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
                Switch(
                    checked = option in selected,
                    onCheckedChange = { checked ->
                        val updated = (
                            if (checked) selected + option else selected - option
                            ).sortedBy { field.options.indexOf(it) }
                        onChanged(field.name, canonicalMethodArray(updated))
                    },
                    enabled = enabled,
                    modifier = Modifier.testTag("method_select_$option"),
                )
            }
        }
    }
}
```

(If `remember`/`Arrangement`/`Row`/`Switch`/`testTag` imports are missing in `UiComponents.kt`, add them; most are already imported — check the existing import block.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest --tests "dev.zerodpi.android.ui.MethodSelectControlTest"`
Expected: PASS.

- [ ] **Step 5: Run existing UI tests to catch regressions**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest --tests "dev.zerodpi.android.ui.DashboardScreenTest"`
Expected: PASS (BYPASS_METHOD now renders as a checklist; if `DashboardScreenTest` asserted the old dropdown, update those assertions in this step).

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/ui/UiComponents.kt android/app/src/androidTest/java/dev/zerodpi/android/ui/MethodSelectControlTest.kt
git commit -m "feat(android): add multi-select control for bypass and method-scan lists"
```

---

### Task 5: Update bundled assets config.toml

**Files:**
- Modify: `android/app/src/main/assets/zerodpi/config.toml`
- Test: `android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt` (add bundled-config test)

**Interfaces:**
- Consumes: fields from Task 2 (bundled file must pass `ZeroDpiConfigToml.analyze` with zero issues).
- Produces: up-to-date first-run config for all profiles.

- [ ] **Step 1: Write the failing test**

Append to `ZeroDpiConfigSchemaTest.kt`:

```kotlin
    @Test
    fun bundledAndroidConfigParsesCleanly() {
        val bundled = findRepoFile("android/app/src/main/assets/zerodpi/config.toml")
        assertTrue("Missing bundled config at ${bundled.absolutePath}", bundled.isFile)
        val editorState = ZeroDpiConfigToml.analyze(bundled.readText())
        assertTrue("Bundled config has issues: ${editorState.issues}", editorState.canStart)
        assertEquals(listOf("wrong_seq", "tls_frag"), editorState.config.methodList("BYPASS_METHOD"))
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: FAIL — bundled file lacks `DISORDER_*`/`METHOD_SCAN_*` etc. is fine (absent fields fall back to defaults), but it fails because it still sets `LOW_TTL_DISCOVER_TIMEOUT_MS = 1500` while... no — 1500 is valid. It FAILS because the file contains legacy `BYPASS_METHOD = "wrong_seq_tls_frag"` (alias parses fine) — the real failure: it sets `SNI_SPLIT_POSITION`/`TLS_PADDING_POSITION` etc.? The file has values that must be valid — the expected failure is `assertTrue(canStart)` failing on unknown-field issues for lines the Android schema now flags, e.g. nothing. Regardless: run it; expected FAIL at least on `LOW_TTL_DISCOVER_TIMEOUT_MS` = 1500 being below 100? No, 1500 ≥ 100 is fine. The genuine expected failure: the bundled file's `BYPASS_METHOD = "wrong_seq_tls_frag"` produces `methodList` = `[wrong_seq, tls_frag]` (passes). If the test unexpectedly passes, still perform Step 3 — the point is the file must be refreshed to mirror the repo file. Expected FAIL is the likely outcome because the bundled file predates the schema and contains e.g. `IP_FRAG_SIZE`-style keys it does not know → "unknown config field" issues. Accept either FAIL or PASS at this step, proceed to Step 3, and re-run.

- [ ] **Step 3: Update the bundled file**

Synchronize `android/app/src/main/assets/zerodpi/config.toml` with the repo `config.toml` sections for the new features. Copy **verbatim** (including comment text) from `config.toml`:

- Mode docs: lines 25–42 (add `sni_method_scan` / `ip_method_scan` bullets).
- `METHOD_SCAN_*` block: lines 114–138.
- `LOW_TTL_*` block: lines 394–455 — **note** the bundled file currently has `LOW_TTL_DISCOVER_TIMEOUT_MS = 1500`; replace with `5000` to match both repo `config.toml` and the core default.
- `FAKE_TLS_*` block: lines 756–796.
- `IP_FRAG_*` block: lines 811–826.
- `DISORDER_*` block: lines 841–873.
- `SNI_SPLIT_*` block: lines 595–611.
- `SNI_BOUNDARY_FRAG_*` block: lines 918–933.
- `TLS_PADDING_*` block: lines 982–1007 (values at 1001/1007).
- `MIXED_CASE_SNI_FLIP_ALL`: lines 1017–1019.
- `CCS_PREFIX_RECORD_VERSION`: lines 1027–1029.
- Updated `BYPASS_METHOD` docs: lines 198–290 of repo `config.toml` (combo rules) — copy the comment block above `BYPASS_METHOD`; keep the actual value as the legacy alias `BYPASS_METHOD = "wrong_seq_tls_frag"` (still valid input and parses to `[wrong_seq, tls_frag]`).

Insert each block next to its existing section in the bundled file (the bundled file already has `low_ttl`, `urg_sni_split`, `tls_padding` comment sections — replace those with the repo versions and add the missing ones). Preserve the file's existing sections that have no changes.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: PASS — `bundledAndroidConfigParsesCleanly` green, zero issues.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/assets/zerodpi/config.toml android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt
git commit -m "feat(android): refresh bundled config.toml with new method sections"
```

---

### Task 6: Service scan-progress state for method-scan runs

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt`
- Test: `android/app/src/test/java/dev/zerodpi/android/runtime/RuntimeEventLineParserTest.kt` (create)

**Interfaces:**
- Consumes: `ZeroDpiRunnerEvent.ScanStarted/ScanProgress/ScanCompleted` (existing; parser already extracts `phase`).
- Produces (used by Task 9):
  - `data class ScanProgressInfo(val scan: String, val phase: String?, val completed: Int?, val total: Int?)` (same file as `ZeroDpiServiceState`).
  - `ZeroDpiServiceState.scanProgress: ScanProgressInfo?` — non-null while a scan/method-scan run is active; cleared on `ScanCompleted` and on state resets.

- [ ] **Step 1: Write the failing test**

Create `android/app/src/test/java/dev/zerodpi/android/runtime/RuntimeEventLineParserTest.kt`:

```kotlin
package dev.zerodpi.android.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class RuntimeEventLineParserTest {
    @Test
    fun parsesMethodScanProgressEventWithPhase() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"scan_progress","scan":"proxy","phase":"method_test","completed":2,"total":5,"sni":"example.com","ip":"1.2.3.4","score":85}""",
        )
        val progress = event as ZeroDpiRunnerEvent.ScanProgress
        assertEquals("method_test", progress.phase)
        assertEquals(2, progress.completed)
        assertEquals(5, progress.total)
    }

    @Test
    fun parsesScanStartedWithTotal() {
        val event = RuntimeEventLineParser.parse("""{"event":"scan_started","scan":"sni","total":12}""")
        val started = event as ZeroDpiRunnerEvent.ScanStarted
        assertEquals("sni", started.scan)
        assertEquals(12, started.total)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.runtime.RuntimeEventLineParserTest"`
Expected: FAIL if the parser/event classes do not expose these fields as named here (verify against `ZeroDpiRunner.kt` lines 28–44: fields are `scan`, `phase`, `completed`, `total`, `sni`, `ip`, `score` — if any name differs, fix the test to match the real names, then expect the test to fail only on any missing `phase` in `ScanProgress`; if it passes immediately, skip to Step 4 and record that the parser already covers it).

- [ ] **Step 3: Add ScanProgressInfo and update handlers**

In `ZeroDpiService.kt`, next to `ZeroDpiServiceState` add:

```kotlin
data class ScanProgressInfo(
    val scan: String,
    val phase: String? = null,
    val completed: Int? = null,
    val total: Int? = null,
)
```

Add to `ZeroDpiServiceState`:

```kotlin
    val scanProgress: ScanProgressInfo? = null,
```

Update the three resets that set `activeTarget = "None"` (lines ~176, ~230, ~370 — each is inside a `state.update { it.copy(...) }` block) to also clear progress:

```kotlin
                        activeTarget = "None",
                        activeTargetScore = null,
                        scanProgress = null,
```

Update the `ScanStarted` handler:

```kotlin
            is ZeroDpiRunnerEvent.ScanStarted -> {
                val total = event.total?.let { " ($it candidates)" }.orEmpty()
                state.update {
                    it.copy(
                        status = RuntimeStatus.Scanning,
                        activeTarget = "Scanning ${event.scan}$total",
                        activeTargetScore = null,
                        scanProgress = ScanProgressInfo(scan = event.scan, total = event.total),
                    )
                }
                appendLog("Started ${event.scan} scan$total.")
            }
```

Update the `ScanProgress` handler:

```kotlin
            is ZeroDpiRunnerEvent.ScanProgress -> {
                val progress = event.total?.let { "${event.completed}/$it" } ?: event.completed.toString()
                state.update {
                    it.copy(
                        status = RuntimeStatus.Scanning,
                        activeTarget = displayTarget(event.sni, event.ip).ifBlank { "Scanning ${event.scan}" },
                        activeTargetScore = event.score,
                        scanProgress = ScanProgressInfo(
                            scan = event.scan,
                            phase = event.phase,
                            completed = event.completed,
                            total = event.total,
                        ),
                    )
                }
                appendLog("${event.scan} scan progress: $progress.")
            }
```

Update the `ScanCompleted` handler to clear progress:

```kotlin
            is ZeroDpiRunnerEvent.ScanCompleted -> {
                state.update { it.copy(scanProgress = null) }
                appendLog("${event.scan} scan completed with ${event.results} result(s).")
            }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.runtime.RuntimeEventLineParserTest"` then `cd android && ./gradlew.bat assembleDebug`
Expected: tests PASS; app compiles.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt android/app/src/test/java/dev/zerodpi/android/runtime/RuntimeEventLineParserTest.kt
git commit -m "feat(android): track scan progress phases in service state"
```

---

### Task 7: Resolve and read METHOD_SCAN_OUTPUT

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/storage/RuntimeStorage.kt`, `android/app/src/main/java/dev/zerodpi/android/storage/SupportBundle.kt`
- Test: `android/app/src/androidTest/java/dev/zerodpi/android/storage/RuntimeStorageInstrumentedTest.kt` (add a test)

**Interfaces:**
- Consumes: `resolveConfigPaths` (existing), `ResolvedRuntimeConfigPaths`.
- Produces (used by Task 9):
  - `ResolvedRuntimeConfigPaths.methodScanOutput: File?`
  - `suspend fun RuntimeStorage.readMethodScanOutput(profileId: String, configText: String): String?` — returns file text or null.

- [ ] **Step 1: Write the failing test**

Open `RuntimeStorageInstrumentedTest.kt` and append (uses the existing test scaffolding; adapt `getStorage()`/profile helpers to the names already used in that file):

```kotlin
    @Test
    fun resolvesAndReadsMethodScanOutput() = runBlocking {
        val storage = storageUnderTest()
        val configText = """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_method_scan"
            METHOD_SCAN_OUTPUT = "method_scan_output.json"
        """.trimIndent()
        val paths = storage.resolveConfigPaths(configText, File(appContext.filesDir, "runtime/dummy"))
        assertNotNull(paths.methodScanOutput)
        assertEquals("method_scan_output.json", paths.methodScanOutput?.name)

        val profileId = "default"
        storage.save(profileId, RuntimeFileKind.Config, configText)
        storage.readMethodScanOutput(profileId, configText) // null: file not written yet
        val target = paths.methodScanOutput!!
        target.parentFile?.mkdirs()
        target.writeText("""{"mode":"sni_method_scan"}""")
        assertEquals("""{"mode":"sni_method_scan"}""", storage.readMethodScanOutput(profileId, configText))
    }
```

(Import `File`, `assertNotNull`, `runBlocking` if not already present.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest --tests "dev.zerodpi.android.storage.RuntimeStorageInstrumentedTest"`
Expected: FAIL — `methodScanOutput` unresolved / always null.

- [ ] **Step 3: Implement**

In `RuntimeStorage.kt`, extend the data class and resolver:

```kotlin
data class ResolvedRuntimeConfigPaths(
    val sniList: File,
    val ipList: File,
    val scanOutput: File?,
    val methodScanOutput: File?,
)
```

```kotlin
            methodScanOutput = readTomlString(configText, "METHOD_SCAN_OUTPUT")
                ?.takeIf { it.isNotBlank() }
                ?.let { resolveRuntimePath(it, runtimeDir) },
```

Update both `ensureDirectory` call sites (lines ~149 and ~171) so the method-scan parent directory is created too:

```kotlin
            resolvedPaths.scanOutput?.parentFile?.let(RuntimeFileOps::ensureDirectory)
            resolvedPaths.methodScanOutput?.parentFile?.let(RuntimeFileOps::ensureDirectory)
```

Add the reader next to `readAll`:

```kotlin
    suspend fun readMethodScanOutput(profileId: String, configText: String): String? =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            val resolved = resolveConfigPaths(configText, currentFiles.runtimeDir)
            resolved.methodScanOutput
                ?.takeIf { it.isFile }
                ?.readText(StandardCharsets.UTF_8)
        }
```

In `SupportBundle.kt`, add `"METHOD_SCAN_OUTPUT"` to `redactedConfigFields`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest --tests "dev.zerodpi.android.storage.RuntimeStorageInstrumentedTest"`
Expected: PASS (existing tests plus the new one).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/storage/RuntimeStorage.kt android/app/src/main/java/dev/zerodpi/android/storage/SupportBundle.kt android/app/src/androidTest/java/dev/zerodpi/android/storage/RuntimeStorageInstrumentedTest.kt
git commit -m "feat(android): resolve and read method-scan output files"
```

---

### Task 8: Start wiring — auto-fill output path, list blocking, display formatting

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/config/ZeroDpiConfig.kt` (helper), `android/app/src/main/java/dev/zerodpi/android/ui/MainViewModel.kt`, `android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt` (label formatting)
- Test: `android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt`

**Interfaces:**
- Consumes: `methodScanModes` (Task 2), `displayMethodList` (Task 1).
- Produces (used by Task 9):
  - `ZeroDpiConfigToml.methodScanStartConfigText(configText: String): String` — returns config text with `METHOD_SCAN_OUTPUT = "method_scan_output.json"` appended when MODE is a method-scan mode and the field is blank; unchanged otherwise.
  - `RuntimeFilesUiState.blockingListIssuesForStart` includes method-scan modes.

- [ ] **Step 1: Write the failing tests**

Append to `ZeroDpiConfigSchemaTest.kt`:

```kotlin
    @Test
    fun methodScanStartConfigTextInjectsOutputPathOnlyForMethodScanModes() {
        val base = """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_method_scan"
            """.trimIndent()
        val injected = ZeroDpiConfigToml.methodScanStartConfigText(base)
        assertTrue(injected.contains("""METHOD_SCAN_OUTPUT = "method_scan_output.json""""))
        assertEquals(listOf("wrong_seq", "tls_frag"), ZeroDpiConfigToml.analyze(injected).config.methodList("BYPASS_METHOD"))

        val withPath = base + "\nMETHOD_SCAN_OUTPUT = \"custom.json\"\n"
        assertEquals(withPath, ZeroDpiConfigToml.methodScanStartConfigText(withPath))

        val spoof = base.replace("sni_method_scan", "sni_spoof")
        assertEquals(spoof, ZeroDpiConfigToml.methodScanStartConfigText(spoof))
    }

    @Test
    fun displayMethodListJoinsMethods() {
        assertEquals("wrong_seq + tls_frag", ZeroDpiConfigToml.displayMethodList("""["wrong_seq", "tls_frag"]"""))
        assertEquals("bogus", ZeroDpiConfigToml.displayMethodList("bogus"))
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"`
Expected: FAIL — `methodScanStartConfigText` unresolved.

- [ ] **Step 3: Implement the helper**

In `ZeroDpiConfigToml` add:

```kotlin
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
```

- [ ] **Step 4: Wire into MainViewModel.start and list blocking**

In `MainViewModel.kt`, update `blockingListIssuesForStart`:

```kotlin
    val blockingListIssuesForStart: List<RuntimeListIssue>
        get() = when (configEditor.valueFor("MODE")) {
            "sni_scan",
            "sni_spoof",
            "proxy_scan",
            "sni_method_scan",
            -> sniListValidation.issues

            "ip_scan",
            "ip_bypass",
            "ip_bypass_plus",
            "ip_method_scan",
            -> ipListValidation.issues

            else -> emptyList()
        }
```

In `start()`, after the `blockingListIssues` check and before `_runtimeFilesState.update { ... statusMessage = validation.rootRequirement.message ... }`, add the injection:

```kotlin
            val startConfigText = ZeroDpiConfigToml.methodScanStartConfigText(
                _runtimeFilesState.value.configText,
            )
            if (startConfigText != _runtimeFilesState.value.configText) {
                _runtimeFilesState.update { current ->
                    current
                        .withText(RuntimeFileKind.Config, startConfigText)
                        .copy(
                            configEditor = ZeroDpiConfigToml.analyze(startConfigText),
                            dirtyFiles = current.dirtyFiles + RuntimeFileKind.Config,
                        )
                }
            }
```

In `syncIdleRuntimeStateFromConfig`, format the bypass label:

```kotlin
            val bypassMethod = ZeroDpiConfigToml.displayMethodList(
                configEditor.valueFor("BYPASS_METHOD"),
            ).ifBlank { current.bypassMethod }
```

In `ZeroDpiService.kt` (line ~220), format the label the same way:

```kotlin
        val bypassMethod = ZeroDpiConfigToml.displayMethodList(
            editorState.valueFor("BYPASS_METHOD"),
        ).ifBlank { "unknown" }
```

(import already exists in the service for `ZeroDpiConfigToml` — verify; add if missing.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.config.ZeroDpiConfigSchemaTest"` then `cd android && ./gradlew.bat assembleDebug`
Expected: tests PASS; app compiles.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/config/ZeroDpiConfig.kt android/app/src/main/java/dev/zerodpi/android/ui/MainViewModel.kt android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt android/app/src/test/java/dev/zerodpi/android/config/ZeroDpiConfigSchemaTest.kt
git commit -m "feat(android): auto-fill method-scan output path and format method lists"
```

---

### Task 9: Method-scan report model, parser, and Home-tab results card

**Files:**
- Create: `android/app/src/main/java/dev/zerodpi/android/methodscan/MethodScanReportModel.kt`
- Create: `android/app/src/main/java/dev/zerodpi/android/methodscan/MethodScanReportParser.kt`
- Create: `android/app/src/main/java/dev/zerodpi/android/ui/MethodScanCard.kt`
- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/MainViewModel.kt`, `android/app/src/main/java/dev/zerodpi/android/MainActivity.kt`, `android/app/src/main/java/dev/zerodpi/android/ui/DashboardScreen.kt`, `android/app/src/main/java/dev/zerodpi/android/ui/HomeScreen.kt`, `android/app/src/main/res/values/strings.xml`
- Test: `android/app/src/test/java/dev/zerodpi/android/methodscan/MethodScanReportParserTest.kt` (create), `android/app/src/androidTest/java/dev/zerodpi/android/ui/MethodScanCardTest.kt` (create)

**Interfaces:**
- Consumes: `ScanProgressInfo` (Task 6), `readMethodScanOutput` (Task 7), `methodScanModes` (Task 2).
- Produces:
  - `MethodScanReportModel`, `MethodScanEntryModel` (`@Serializable`).
  - `MethodScanReportParser.parse(json: String): MethodScanReportModel?`.
  - `MethodScanPhase` (sealed: `Hidden`, `Idle`, `Running`, `Completed`, `Failed(message)`), `MethodScanUiState(phase, mode, progress, report)` — placed in `MainViewModel.kt`.
  - `MainViewModel.methodScanState: StateFlow<MethodScanUiState>`.
  - `MethodScanCard(state: MethodScanUiState, modifier)` composable with testTags `method_scan_card`, `method_scan_progress`, `method_scan_row_<method>`, `method_scan_error`.

- [ ] **Step 1: Write the failing parser test**

Create `android/app/src/test/java/dev/zerodpi/android/methodscan/MethodScanReportParserTest.kt`:

```kotlin
package dev.zerodpi.android.methodscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MethodScanReportParserTest {
    private val sample = """
        {
          "mode": "sni_method_scan",
          "target_sni": "example.com",
          "target_ip": "1.2.3.4",
          "target_score": 99,
          "samples_per_method": 3,
          "interval_ms": 1000,
          "methods": [
            {
              "method": "wrong_seq",
              "samples_total": 3,
              "samples_ok": 3,
              "success_rate": 100.0,
              "avg_ttfb_ms": 120.5,
              "min_ttfb_ms": 110,
              "max_ttfb_ms": 131,
              "avg_tls_ms": 40.0,
              "http_status": 200,
              "last_error": null
            },
            {
              "method": "tls_frag",
              "samples_total": 3,
              "samples_ok": 1,
              "success_rate": 33.33,
              "avg_ttfb_ms": 300.0,
              "min_ttfb_ms": 300,
              "max_ttfb_ms": 300,
              "avg_tls_ms": null,
              "http_status": null,
              "last_error": "handshake timeout"
            }
          ]
        }
    """.trimIndent()

    @Test
    fun parsesMethodScanReport() {
        val report = MethodScanReportParser.parse(sample)
        assertEquals("sni_method_scan", report?.mode)
        assertEquals("example.com", report?.targetSni)
        assertEquals(2, report?.methods?.size)
        assertEquals("wrong_seq", report?.methods?.get(0)?.method)
        assertEquals(100.0, report?.methods?.get(0)?.successRate ?: 0.0, 0.001)
        assertEquals("handshake timeout", report?.methods?.get(1)?.lastError)
    }

    @Test
    fun ignoresUnknownKeysAndRejectsMalformedJson() {
        assertNull(MethodScanReportParser.parse("not json"))
        assertNull(MethodScanReportParser.parse("""{"mode": 5}"""))
        assertEquals("ip_method_scan", MethodScanReportParser.parse("""{"mode":"ip_method_scan","target_sni":"a","target_ip":"1.1.1.1","target_score":1,"samples_per_method":1,"interval_ms":0,"methods":[],"extra":true}""")?.mode)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.methodscan.MethodScanReportParserTest"`
Expected: FAIL — package/classes missing.

- [ ] **Step 3: Implement the model and parser**

Create `android/app/src/main/java/dev/zerodpi/android/methodscan/MethodScanReportModel.kt`:

```kotlin
package dev.zerodpi.android.methodscan

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MethodScanEntryModel(
    val method: String,
    @SerialName("samples_total") val samplesTotal: Int,
    @SerialName("samples_ok") val samplesOk: Int,
    @SerialName("success_rate") val successRate: Double,
    @SerialName("avg_ttfb_ms") val avgTtfbMs: Double? = null,
    @SerialName("avg_tls_ms") val avgTlsMs: Double? = null,
    @SerialName("http_status") val httpStatus: Int? = null,
    @SerialName("last_error") val lastError: String? = null,
)

@Serializable
data class MethodScanReportModel(
    val mode: String,
    @SerialName("target_sni") val targetSni: String,
    @SerialName("target_ip") val targetIp: String,
    @SerialName("target_score") val targetScore: Int,
    @SerialName("samples_per_method") val samplesPerMethod: Int,
    @SerialName("interval_ms") val intervalMs: Long,
    val methods: List<MethodScanEntryModel>,
)
```

Create `android/app/src/main/java/dev/zerodpi/android/methodscan/MethodScanReportParser.kt`:

```kotlin
package dev.zerodpi.android.methodscan

import kotlinx.serialization.json.Json

object MethodScanReportParser {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(text: String): MethodScanReportModel? =
        runCatching { json.decodeFromString<MethodScanReportModel>(text) }.getOrNull()
}
```

- [ ] **Step 4: Run parser test to verify it passes**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.methodscan.MethodScanReportParserTest"`
Expected: PASS.

- [ ] **Step 5: Add MethodScanUiState and ViewModel orchestration**

In `MainViewModel.kt`, add next to `RuntimeFilesUiState`:

```kotlin
sealed interface MethodScanPhase {
    data object Hidden : MethodScanPhase
    data object Idle : MethodScanPhase
    data object Running : MethodScanPhase
    data object Completed : MethodScanPhase
    data class Failed(val message: String) : MethodScanPhase
}

data class MethodScanUiState(
    val phase: MethodScanPhase = MethodScanPhase.Hidden,
    val mode: String? = null,
    val progress: ScanProgressInfo? = null,
    val report: MethodScanReportModel? = null,
)
```

(import `dev.zerodpi.android.service.ScanProgressInfo` and `dev.zerodpi.android.methodscan.*` at the top of `MainViewModel.kt`.)

Add to the class:

```kotlin
    private val _methodScanState = MutableStateFlow(MethodScanUiState())
    val methodScanState: StateFlow<MethodScanUiState> = _methodScanState.asStateFlow()

    private var lastServiceStatus: RuntimeStatus? = null

    private fun updateMethodScanState(serviceState: ZeroDpiServiceState) {
        val mode = _runtimeFilesState.value.configEditor.valueFor("MODE")
        val visible = mode in ZeroDpiConfigSchema.methodScanModes
        if (!visible) {
            lastServiceStatus = serviceState.status
            _methodScanState.value = MethodScanUiState()
            return
        }

        val previous = lastServiceStatus
        lastServiceStatus = serviceState.status
        val transient = serviceState.status in setOf(
            RuntimeStatus.Starting, RuntimeStatus.Scanning, RuntimeStatus.Restarting,
        )
        if (transient) {
            _methodScanState.value = MethodScanUiState(
                phase = MethodScanPhase.Running,
                mode = mode,
                progress = serviceState.scanProgress,
            )
            return
        }

        if (previous != null && previous in setOf(
                RuntimeStatus.Starting, RuntimeStatus.Scanning, RuntimeStatus.Restarting,
            )
        ) {
            val profileId = _runtimeFilesState.value.activeProfileId
            val configText = _runtimeFilesState.value.configText
            viewModelScope.launch {
                val raw = runCatching { runtimeStorage.readMethodScanOutput(profileId, configText) }.getOrNull()
                val report = raw?.let { MethodScanReportParser.parse(it) }
                _methodScanState.value = MethodScanUiState(
                    phase = if (report != null) {
                        MethodScanPhase.Completed
                    } else {
                        MethodScanPhase.Failed(
                            serviceState.lastError
                                ?.let { "Method scan failed: $it" }
                                ?: "Method scan finished without a report.",
                        )
                    },
                    mode = mode,
                    report = report,
                )
            }
            return
        }

        _methodScanState.value = MethodScanUiState(phase = MethodScanPhase.Idle, mode = mode)
    }
```

Call sites:
- In `onServiceConnected`, inside the `service?.state()?.collect { state -> ... }` lambda after `_uiState.value = state`: add `updateMethodScanState(state)`.
- In `onServiceDisconnected`, after `_uiState.value = _uiState.value.copy(status = RuntimeStatus.Stopped)`: add `updateMethodScanState(_uiState.value)`.
- At the end of `syncIdleRuntimeStateFromConfig` (after the `_uiState.update { ... }` block): add `updateMethodScanState(_uiState.value)` — this recomputes visibility/Idle whenever the config editor changes while stopped.

- [ ] **Step 6: Write the failing card UI test**

Create `android/app/src/androidTest/java/dev/zerodpi/android/ui/MethodScanCardTest.kt`:

```kotlin
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
```

- [ ] **Step 7: Run test to verify it fails**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest --tests "dev.zerodpi.android.ui.MethodScanCardTest"`
Expected: FAIL — `MethodScanCard` unresolved.

- [ ] **Step 8: Implement the card and strings**

Add to `android/app/src/main/res/values/strings.xml`:

```xml
    <string name="method_scan_title">Method scan</string>
    <string name="method_scan_idle">Mode %1$s is selected. Press Start to test every configured method against the best candidate.</string>
    <string name="method_scan_running">Testing bypass methods…</string>
    <string name="method_scan_progress">Method %1$s of %2$s</string>
    <string name="method_scan_completed">Tested %1$d methods against %2$s (%3$s, score %4$d).</string>
    <string name="method_scan_failed">Method scan finished without results.</string>
    <string name="method_scan_column_rank">#</string>
    <string name="method_scan_column_method">Method</string>
    <string name="method_scan_column_success">Success</string>
    <string name="method_scan_column_samples">Samples</string>
    <string name="method_scan_column_ttfb">Avg TTFB</string>
    <string name="method_scan_column_tls">Avg TLS</string>
    <string name="method_scan_column_http">HTTP</string>
    <string name="method_scan_value_na">—</string>
```

Create `android/app/src/main/java/dev/zerodpi/android/ui/MethodScanCard.kt`:

```kotlin
package dev.zerodpi.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.methodscan.MethodScanEntryModel
import dev.zerodpi.android.methodscan.MethodScanReportModel

@Composable
internal fun MethodScanCard(
    state: MethodScanUiState,
    modifier: Modifier = Modifier,
) {
    when (state.phase) {
        MethodScanPhase.Hidden -> Unit

        MethodScanPhase.Idle -> SectionCard(
            title = stringResource(R.string.method_scan_title),
            modifier = modifier.testTag("method_scan_card"),
        ) {
            Text(stringResource(R.string.method_scan_idle, state.mode.orEmpty()))
        }

        MethodScanPhase.Running -> {
            val completed = state.progress?.completed ?: 0
            val total = state.progress?.total ?: 1
            SectionCard(
                title = stringResource(R.string.method_scan_title),
                modifier = modifier.testTag("method_scan_card"),
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.method_scan_running))
                    LinearProgressIndicator(
                        progress = { (completed.toFloat() / total.coerceAtLeast(1)).coerceIn(0f, 1f) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("method_scan_progress"),
                    )
                    Text(
                        text = stringResource(R.string.method_scan_progress, completed, total),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }

        MethodScanPhase.Completed -> ResultsCard(state.report, modifier)

        is MethodScanPhase.Failed -> SectionCard(
            title = stringResource(R.string.method_scan_title),
            modifier = modifier.testTag("method_scan_card"),
        ) {
            Text(
                text = state.message,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag("method_scan_error"),
            )
        }
    }
}

@Composable
private fun ResultsCard(report: MethodScanReportModel?, modifier: Modifier) {
    if (report == null) return
    SectionCard(
        title = stringResource(R.string.method_scan_title),
        modifier = modifier.testTag("method_scan_card"),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                stringResource(
                    R.string.method_scan_completed,
                    report.methods.size,
                    report.targetSni,
                    report.targetIp,
                    report.targetScore,
                ),
            )
            Row(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.method_scan_column_rank), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(3f)) {
                    Text(stringResource(R.string.method_scan_column_method), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.method_scan_column_success), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.method_scan_column_ttfb), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.method_scan_column_tls), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.method_scan_column_http), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
            }
            report.methods.forEachIndexed { index, entry ->
                MethodScanRow(index, entry)
            }
        }
    }
}

@Composable
private fun MethodScanRow(index: Int, entry: MethodScanEntryModel) {
    val na = stringResource(R.string.method_scan_value_na)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("method_scan_row_${entry.method}"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text((index + 1).toString(), style = MaterialTheme.typography.bodySmall)
        }
        Column(modifier = Modifier.weight(3f)) {
            Text(entry.method, style = MaterialTheme.typography.bodySmall)
            entry.lastError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall) }
        }
        Column(modifier = Modifier.weight(2f)) {
            Text("%.0f%%".format(entry.successRate), style = MaterialTheme.typography.bodySmall)
            Text("${entry.samplesOk}/${entry.samplesTotal}", style = MaterialTheme.typography.labelSmall)
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.avgTtfbMs?.let { "%.0f ms".format(it) } ?: na, style = MaterialTheme.typography.bodySmall)
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.avgTlsMs?.let { "%.0f ms".format(it) } ?: na, style = MaterialTheme.typography.bodySmall)
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.httpStatus?.toString() ?: na, style = MaterialTheme.typography.bodySmall)
        }
    }
}
```

(`SectionCard` is an existing composable in `UiComponents.kt` with signature `SectionCard(title: String, modifier: Modifier = Modifier, content: @Composable () -> Unit)` — the card code above already wraps content in an explicit `Column`, which satisfies this signature.)

- [ ] **Step 9: Wire the card through MainActivity → DashboardScreen → HomeScreen**

`MainActivity.kt` — collect the new flow and pass it down:

```kotlin
            val methodScanState by viewModel.methodScanState.collectAsState()
```

and add `methodScanState = methodScanState,` to the `DashboardScreen(...)` call.

`DashboardScreen.kt` — add parameter `methodScanState: MethodScanUiState,` to the signature and forward it to `HomeScreen(methodScanState = methodScanState, ...)` (find the existing `HomeScreen(...)` call inside `DashboardScreen`'s `when (destination)` and add the argument).

`HomeScreen.kt` — add parameter `methodScanState: MethodScanUiState,` and insert the card right after the `RuntimeStatusCard(...)` call:

```kotlin
        MethodScanCard(state = methodScanState)
```

Check `DashboardScreenTest.kt` and `MainViewModelInstrumentedTest.kt` call sites of `DashboardScreen`/`HomeScreen` — update them to pass a default `MethodScanUiState()`.

- [ ] **Step 10: Run all tests to verify they pass**

Run:
```bash
cd android && ./gradlew.bat testDebugUnitTest
cd android && ./gradlew.bat connectedDebugAndroidTest --tests "dev.zerodpi.android.ui.MethodScanCardTest" --tests "dev.zerodpi.android.ui.DashboardScreenTest"
cd android && ./gradlew.bat assembleDebug
```
Expected: all green.

- [ ] **Step 11: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/methodscan android/app/src/main/java/dev/zerodpi/android/ui/MethodScanCard.kt android/app/src/main/java/dev/zerodpi/android/ui/MainViewModel.kt android/app/src/main/java/dev/zerodpi/android/MainActivity.kt android/app/src/main/java/dev/zerodpi/android/ui/DashboardScreen.kt android/app/src/main/java/dev/zerodpi/android/ui/HomeScreen.kt android/app/src/main/res/values/strings.xml android/app/src/test/java/dev/zerodpi/android/methodscan android/app/src/androidTest/java/dev/zerodpi/android/ui/MethodScanCardTest.kt
git commit -m "feat(android): add method-scan results card with live progress"
```

---

### Task 10: README note + full verification + packaging

**Files:**
- Modify: `README.md` (Android section — find the heading that describes the Android app; if none exists, add a short `## Android app` section near the top-level usage docs)

**Interfaces:** none (documentation + verification only).

- [ ] **Step 1: Document parity in README**

In `README.md`, under the Android app section (or a new `## Android app` section after the main usage docs), add:

```markdown
The Android app exposes the full core configuration: all eight operating
modes (including `sni_method_scan` / `ip_method_scan`), all sixteen base
bypass methods as a multi-select list (`BYPASS_METHOD`), and every
per-method parameter group (`low_ttl`, `fake_tls`, `ip_frag`, `disorder`,
`urg_sni_split`, `sni_boundary_frag`, `tls_padding`, `mixed_case_sni`,
`ccs_prefix`) under Configure → Advanced. When a method-scan mode is
selected, the Home tab shows live progress and a ranked results table
read from `METHOD_SCAN_OUTPUT` (auto-filled to `method_scan_output.json`
in the profile runtime directory when left blank). Socket-only methods
(`tls_frag`, `ccs_prefix`, `tls_padding`, `mixed_case_sni`,
`sni_boundary_frag`) run without root.
```

- [ ] **Step 2: Run the full verification suite**

```bash
cd android && ./gradlew.bat testDebugUnitTest
cd android && ./gradlew.bat lintDebug
cd android && ./gradlew.bat assembleDebug
```
Expected: all green. Instrumented tests (`connectedDebugAndroidTest`) require a device/emulator; run the full suite on one and confirm zero failures.

- [ ] **Step 3: Rebuild the Android binary so the shipped APK embeds current core**

The bundled `jniLibs/libzerodpi_exec.so` must be built from current `master` (it already implements the features — this step only refreshes the artifact):

```bash
python build.py --platform android
```

Expected: `dist/android-app/` contains rebuilt `jniLibs` for the supported ABIs; `./gradlew.bat assembleDebug` still succeeds with the refreshed binary.

- [ ] **Step 4: Manual smoke test (device)**

1. Install the debug APK on a rooted device (or emulator).
2. Configure → Advanced → set `MODE = sni_method_scan`; open Bypass engine and enable `wrong_seq` + `ccs_prefix`; verify the readiness card reports root requirement (wrong_seq needs interception).
3. Press Start → Home shows the method-scan card with progress → after completion a ranked table appears with per-method success rates.
4. Switch `BYPASS_METHOD` to only `ccs_prefix` + `tls_frag` and confirm the readiness card reports **rootless**.
5. Live Logs show the method-scan summary lines.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document Android parity for methods, modes, and method-scan results"
```

---

## Final verification checklist (run before declaring the plan complete)

- [ ] `cd android && ./gradlew.bat testDebugUnitTest` — all unit tests pass, including `schemaFieldsMatchRustConfigFields` (99-field parity).
- [ ] `cd android && ./gradlew.bat lintDebug` — no new lint errors.
- [ ] `cd android && ./gradlew.bat assembleDebug` — APK builds.
- [ ] Instrumented suites pass on a device: `ZeroDpiConfigSchemaTest` (unit), `MethodSelectControlTest`, `MethodScanCardTest`, `DashboardScreenTest`, `RuntimeStorageInstrumentedTest`, `MainViewModelInstrumentedTest`.
- [ ] `python build.py --platform android` produces the refreshed binary; APK still assembles.
- [ ] `cargo build --workspace --release` untouched (no Rust diffs in `git status` under `crates/`).
