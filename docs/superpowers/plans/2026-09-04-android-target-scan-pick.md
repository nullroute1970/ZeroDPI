# Android Target Scan & Pick Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the desktop "select an SNI/IP after scan" behavior (`AUTO_SELECT = false`) to the Android app: a Home-tab target-picker card, a Start-flow scan gate, a mid-run "Scan & choose" restart flow, and an app-side persisted target pin injected into ephemeral run configs — with zero Rust changes.

**Architecture:** All work is Kotlin in `android/app`. Scan results come from the binary's existing `sni_scan`/`ip_scan` modes plus their `SCAN_OUTPUT` JSON (patched into an ephemeral config file in the profile runtime dir, exactly like the existing test-scan configs). The user's pick is persisted app-side in `target_pin.json` per profile and injected at launch by patching `SELECTED_SNI`/`SELECTED_IP` into an ephemeral `.run_config.toml` passed as `--config`; the user's `config.toml` is never modified. Orchestration lives in `ZeroDpiService` (single data-plane process slot: mid-run re-scan = graceful stop → scan → pick → relaunch), UI state in `MainViewModel`, rendering on the Home tab.

**Tech Stack:** Kotlin, Jetpack Compose (Material 3), StateFlow, kotlinx-serialization-json 1.11.0 (already a dependency), JUnit4 unit tests, Compose androidTest + instrumented service/ViewModel tests that run against the existing `FakeZeroDpiRunner` (active when no native `.so` is packaged and `ZERODPI_ALLOW_FAKE_RUNNER` is set for debug builds).

**Spec:** `docs/superpowers/specs/2026-09-04-android-target-scan-pick-design.md` (approved in chat 2026-09-04; behavior table, persistence rules, and edge-case policies there are normative).

## Global Constraints

- **No Rust / core crate changes.** Do not touch `crates/`, `windivert/`, `Cargo.toml`, or `build.py`. The binary is used exactly as shipped.
- Test commands (run from repo root unless noted): unit `cd android && ./gradlew.bat testDebugUnitTest --tests "<class>"`; instrumented `cd android && ./gradlew.bat connectedDebugAndroidTest` (device/emulator with the debug app; class scoping via `-Pandroid.testInstrumentationRunnerArguments.class=<class>`).
- Repo Kotlin style: 4-space indent, `internal` visibility for UI composables and `internal`/`private` for helpers, strings in `res/values/strings.xml`, `testTag` on every interactive control and card, conventional commits (`feat(android): …`).
- New dependencies: none.
- Existing schema invariant must keep passing: `ZeroDpiConfigSchemaTest.schemaFieldsMatchRustConfigFields` (no new config fields are added; `SCAN_OUTPUT`, `AUTO_SELECT`, `SELECTED_SNI`, `SELECTED_IP` already exist in the schema).
- The runner keeps launching with `--no-tui --auto-select --json-events`; do not change `ProcessZeroDpiRunner`'s command. Once `SELECTED_SNI`/`SELECTED_IP` is in the run config the binary skips scanning regardless.
- Ephemeral config files live in the profile runtime dir so relative paths (`SNI_LIST`, `SCAN_OUTPUT`, …) resolve correctly (`main.rs` resolves relative to the config file's parent).
- Scan JSON shapes (from the binary, arrays of objects): SNI entries `{sni, ip, tcp_latency_ms, tls_ok, tls_latency_ms, cert_valid, ttfb_ms, download_bps, upload_bps, speed_bps, http_status, score}`; IP entries identical minus `sni`. All keys snake_case; numbers nullable except `score`.

## Canonical APIs (defined here once; all tasks reference these)

Package `dev.zerodpi.android.targetscan` (new):

```kotlin
enum class PinKind { Sni, Ip }   // UI/display string maps lowercase "sni"/"ip"

data class TargetPin(kind: PinKind, sni: String?, ip: String, score: Int?, pickedAtMs: Long)
// JSON: {"kind":"sni"|"ip","sni":"...","ip":"1.2.3.4","score":95,"picked_at_ms":...}

object TargetPinCodec { fun encode(pin: TargetPin): String; fun decode(text: String): TargetPin? }

object TargetScanFiles { const val PIN_FILE_NAME = "target_pin.json"; const val PICK_SCAN_RESULTS_FILE_NAME = "pick_scan_results.json" }

object TargetPickPolicy {
    val pickableModes: Set<String>                 // sni_spoof, ip_bypass, ip_bypass_plus
    fun scanModeFor(mode: String): String?         // sni_spoof->sni_scan, ip_*->ip_scan
    fun pinKindForMode(mode: String): PinKind?     // sni_spoof->Sni, ip_*->Ip
    fun isGateEligible(mode, autoSelect: Boolean, selectedSni: String, selectedIp: String, pin: TargetPin?): Boolean
}

@Serializable data class SniScanEntryModel(val sni: String, val ip: String, ...)  // score >= 0
@Serializable data class IpScanEntryModel(val ip: String, ...)
object ScanResultParser { fun parseSni(text: String): List<SniScanEntryModel>?; fun parseIp(text: String): List<IpScanEntryModel>? }
```

Storage (`dev.zerodpi.android.storage`):

```kotlin
class TargetPinStore(context: Context) {
    suspend fun read(profileId: String): TargetPin?
    suspend fun write(profileId: String, pin: TargetPin)
    suspend fun clear(profileId: String)
}
// RuntimeStorage additions:
suspend fun prepareRunConfig(profileId, modeOverride: String? = null,
    patchFields: Map<String, String> = emptyMap(), pin: TargetPin? = null): RuntimeRunConfig
suspend fun readPickScanResults(profileId: String): String?
suspend fun deletePickScanResults(profileId: String)
```

Service (`dev.zerodpi.android.service.ZeroDpiService` + state types):

```kotlin
enum class RuntimeStatus { Stopped, Starting, Scanning, Running, Restarting, Stopping, Failed, Choosing }
enum class PickPhase { Scanning, Choosing }
enum class PickOrigin { StartGate, MidRun, Standalone }
data class PickSessionUi(val phase: PickPhase, val origin: PickOrigin, val mode: String, val resumeAvailable: Boolean)
// ZeroDpiServiceState gains: val pickSession: PickSessionUi? = null
// ZeroDpiService public API gains: fun requestTargetPick(profileId: String); fun applyTargetPick(); fun cancelTargetPick()
```

`MainViewModel` gains `TargetPickUiState` StateFlow and actions; new Home-tab card composable `TargetPickerCard`.

---

### Task 1: Target pin model, codec, and store

**Files:**
- Create: `android/app/src/main/java/dev/zerodpi/android/targetscan/TargetPin.kt` (PinKind, TargetPin, TargetPinCodec, TargetScanFiles)
- Create: `android/app/src/main/java/dev/zerodpi/android/storage/TargetPinStore.kt`
- Test: `android/app/src/test/java/dev/zerodpi/android/targetscan/TargetPinCodecTest.kt`
- Test: `android/app/src/androidTest/java/dev/zerodpi/android/storage/TargetPinStoreInstrumentedTest.kt`

**Interfaces:**
- Produces (used by Tasks 2–8): `PinKind`, `TargetPin`, `TargetPinCodec.encode/decode`, `TargetScanFiles.PIN_FILE_NAME`, `TargetPinStore.read/write/clear(profileId)`.

- [ ] **Step 1: Write the failing unit test**

Create `android/app/src/test/java/dev/zerodpi/android/targetscan/TargetPinCodecTest.kt`:

```kotlin
package dev.zerodpi.android.targetscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TargetPinCodecTest {
    @Test
    fun encodesSniPinWithSnakeCaseKind() {
        val pin = TargetPin(kind = PinKind.Sni, sni = "edge.example.com", ip = "1.2.3.4", score = 95, pickedAtMs = 1_757_000_000_000L)
        val json = TargetPinCodec.encode(pin)
        assertEquals("""{"kind":"sni","sni":"edge.example.com","ip":"1.2.3.4","score":95,"picked_at_ms":1757000000000}""", json)
    }

    @Test
    fun roundTripsIpPinWithoutSni() {
        val pin = TargetPin(kind = PinKind.Ip, sni = null, ip = "104.16.132.229", score = null, pickedAtMs = 42L)
        assertEquals(pin, TargetPinCodec.decode(TargetPinCodec.encode(pin)))
    }

    @Test
    fun returnsNullForGarbage() {
        assertNull(TargetPinCodec.decode("not json"))
        assertNull(TargetPinCodec.decode("""{"ip": 7}"""))
    }

    @Test
    fun ignoresUnknownKeys() {
        val pin = TargetPinCodec.decode(
            """{"kind":"sni","sni":"a.example","ip":"5.6.7.8","extra":true,"picked_at_ms":1}""",
        )
        assertEquals("a.example", pin?.sni)
    }
}
```

- [ ] **Step 2: Run the unit test to verify it fails**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.targetscan.TargetPinCodecTest"`
Expected: compilation fails — package/types unresolved.

- [ ] **Step 3: Implement the model and codec**

Create `android/app/src/main/java/dev/zerodpi/android/targetscan/TargetPin.kt`:

```kotlin
package dev.zerodpi.android.targetscan

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

enum class PinKind {
    @SerialName("sni") Sni,
    @SerialName("ip") Ip,
}

@Serializable
data class TargetPin(
    val kind: PinKind,
    val sni: String? = null,
    val ip: String,
    val score: Int? = null,
    @SerialName("picked_at_ms") val pickedAtMs: Long,
)

object TargetPinCodec {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    fun encode(pin: TargetPin): String = json.encodeToString(TargetPin.serializer(), pin)

    fun decode(text: String): TargetPin? =
        runCatching { json.decodeFromString(TargetPin.serializer(), text) }.getOrNull()
}

object TargetScanFiles {
    const val PIN_FILE_NAME = "target_pin.json"
    const val PICK_SCAN_RESULTS_FILE_NAME = "pick_scan_results.json"
}
```

(`encodeToString`/`decodeFromString` with an explicit serializer work on both kotlinx-serialization 1.x and 1.11-style APIs; if the repo's Json instance imports differ, follow the import style already used in `MethodScanReportParser.kt`, which is `kotlinx.serialization.json.Json` with `json.decodeFromString<T>` — use `Json.encodeToString(serializer, pin)` which exists in all 1.x versions.)

- [ ] **Step 4: Run the unit test to verify it passes**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.targetscan.TargetPinCodecTest"`
Expected: PASS.

- [ ] **Step 5: Implement the store**

Create `android/app/src/main/java/dev/zerodpi/android/storage/TargetPinStore.kt`:

```kotlin
package dev.zerodpi.android.storage

import android.content.Context
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.targetscan.TargetPin
import dev.zerodpi.android.targetscan.TargetPinCodec
import dev.zerodpi.android.targetscan.TargetScanFiles
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.charset.StandardCharsets

class TargetPinStore(context: Context) {
    private val appContext = context.applicationContext
    private val profileRepository = ProfileRepository(appContext)

    suspend fun read(profileId: String): TargetPin? =
        withContext(Dispatchers.IO) {
            fileFor(profileId)
                .takeIf { it.isFile }
                ?.readText(StandardCharsets.UTF_8)
                ?.let(TargetPinCodec::decode)
        }

    suspend fun write(profileId: String, pin: TargetPin) =
        withContext(Dispatchers.IO) {
            RuntimeFileOps.atomicWrite(
                target = fileFor(profileId),
                content = TargetPinCodec.encode(pin),
                backup = null,
            )
        }

    suspend fun clear(profileId: String) =
        withContext(Dispatchers.IO) {
            fileFor(profileId).delete()
        }

    private suspend fun fileFor(profileId: String): File {
        val paths = profileRepository.filePaths(profileId)
        return File(paths.profileDir, TargetScanFiles.PIN_FILE_NAME)
    }
}
```

Note: `ProfileRepository.filePaths(profileId)` is `suspend` (see `ProfileRepository.kt:60`).

- [ ] **Step 6: Write the instrumented store test**

Create `android/app/src/androidTest/java/dev/zerodpi/android/storage/TargetPinStoreInstrumentedTest.kt`:

```kotlin
package dev.zerodpi.android.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.TargetPin
import dev.zerodpi.android.targetscan.TargetScanFiles
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TargetPinStoreInstrumentedTest {
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        runBlocking { clearPinFiles() }
    }

    @Test
    fun writeReadClearRoundTrip() = runBlocking {
        val store = TargetPinStore(context)
        val pin = TargetPin(PinKind.Sni, "edge.example.com", "1.2.3.4", 95, 42L)
        assertNull(store.read(ProfileRepository.DEFAULT_PROFILE_ID))
        store.write(ProfileRepository.DEFAULT_PROFILE_ID, pin)
        assertEquals(pin, store.read(ProfileRepository.DEFAULT_PROFILE_ID))
        store.clear(ProfileRepository.DEFAULT_PROFILE_ID)
        assertNull(store.read(ProfileRepository.DEFAULT_PROFILE_ID))
    }

    private suspend fun clearPinFiles() {
        val repository = ProfileRepository(context)
        val paths = repository.filePaths(ProfileRepository.DEFAULT_PROFILE_ID)
        File(paths.profileDir, TargetScanFiles.PIN_FILE_NAME).delete()
    }
}
```

(Verify `ProfileRepository.DEFAULT_PROFILE_ID` exists; it is referenced as `ZeroDpiProfile.DEFAULT_PROFILE_ID` elsewhere — if only the latter exists, import `dev.zerodpi.android.profile.ZeroDpiProfile` and use `ZeroDpiProfile.DEFAULT_PROFILE_ID`. Check `ProfileRepository.kt` and adjust the import accordingly.)

- [ ] **Step 7: Run the instrumented test**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest`
Expected: `TargetPinStoreInstrumentedTest` PASS (existing tests remain green).

- [ ] **Step 8: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/targetscan/TargetPin.kt android/app/src/main/java/dev/zerodpi/android/storage/TargetPinStore.kt android/app/src/test/java/dev/zerodpi/android/targetscan/TargetPinCodecTest.kt android/app/src/androidTest/java/dev/zerodpi/android/storage/TargetPinStoreInstrumentedTest.kt
git commit -m "feat(android): add target pin model, codec, and per-profile store"
```

---

### Task 2: Scan result models, parser, and pick policy

**Files:**
- Create: `android/app/src/main/java/dev/zerodpi/android/targetscan/ScanResultModels.kt`
- Create: `android/app/src/main/java/dev/zerodpi/android/targetscan/ScanResultParser.kt`
- Create: `android/app/src/main/java/dev/zerodpi/android/targetscan/TargetPickPolicy.kt`
- Test: `android/app/src/test/java/dev/zerodpi/android/targetscan/ScanResultParserTest.kt`
- Test: `android/app/src/test/java/dev/zerodpi/android/targetscan/TargetPickPolicyTest.kt`

**Interfaces:**
- Consumes: `PinKind`, `TargetPin` (Task 1).
- Produces (used by Tasks 5–8): `SniScanEntryModel`, `IpScanEntryModel`, `ScanResultParser.parseSni/parseIp`, `TargetPickPolicy.pickableModes/scanModeFor/pinKindForMode/isGateEligible`.

- [ ] **Step 1: Write the failing unit tests**

Create `android/app/src/test/java/dev/zerodpi/android/targetscan/ScanResultParserTest.kt`:

```kotlin
package dev.zerodpi.android.targetscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ScanResultParserTest {
    private val sniJson = """
        [
          {
            "sni": "auth.vercel.com",
            "ip": "76.76.21.21",
            "tcp_latency_ms": 42,
            "tls_ok": true,
            "tls_latency_ms": 88,
            "cert_valid": true,
            "ttfb_ms": 140,
            "download_bps": 1048576.0,
            "upload_bps": 786432.0,
            "speed_bps": 1048576.0,
            "http_status": 200,
            "score": 91
          },
          {
            "sni": "unreachable.example",
            "ip": "10.0.0.1",
            "tcp_latency_ms": null,
            "tls_ok": false,
            "tls_latency_ms": null,
            "cert_valid": false,
            "ttfb_ms": null,
            "download_bps": null,
            "upload_bps": null,
            "speed_bps": null,
            "http_status": null,
            "score": 0
          }
        ]
    """.trimIndent()

    private val ipJson = """
        [
          {
            "ip": "104.16.132.229",
            "tcp_latency_ms": 35,
            "tls_ok": true,
            "tls_latency_ms": 70,
            "cert_valid": true,
            "ttfb_ms": 120,
            "download_bps": 2048000.0,
            "upload_bps": 1048576.0,
            "speed_bps": 2048000.0,
            "http_status": 200,
            "score": 96
          }
        ]
    """.trimIndent()

    @Test
    fun parsesSniResults() {
        val entries = ScanResultParser.parseSni(sniJson)
        assertEquals(2, entries?.size)
        assertEquals("auth.vercel.com", entries?.get(0)?.sni)
        assertEquals("76.76.21.21", entries?.get(0)?.ip)
        assertEquals(91, entries?.get(0)?.score)
        assertEquals(42L, entries?.get(0)?.tcpLatencyMs)
        assertEquals(0, entries?.get(1)?.score)
    }

    @Test
    fun parsesIpResults() {
        val entries = ScanResultParser.parseIp(ipJson)
        assertEquals(1, entries?.size)
        assertEquals("104.16.132.229", entries?.get(0)?.ip)
        assertEquals(96, entries?.get(0)?.score)
        assertEquals(null, entries?.get(0)?.ttfbMs?.let { it })
    }

    @Test
    fun returnsNullForGarbageAndEmptyArrays() {
        assertNull(ScanResultParser.parseSni("nope"))
        assertNull(ScanResultParser.parseIp("{}"))
        assertEquals(0, ScanResultParser.parseSni("[]")?.size)
        assertEquals(0, ScanResultParser.parseIp("[]")?.size)
    }
}
```

Create `android/app/src/test/java/dev/zerodpi/android/targetscan/TargetPickPolicyTest.kt`:

```kotlin
package dev.zerodpi.android.targetscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetPickPolicyTest {
    @Test
    fun mapsModesToScanKinds() {
        assertEquals("sni_scan", TargetPickPolicy.scanModeFor("sni_spoof"))
        assertEquals("ip_scan", TargetPickPolicy.scanModeFor("ip_bypass"))
        assertEquals("ip_scan", TargetPickPolicy.scanModeFor("ip_bypass_plus"))
        assertNull(TargetPickPolicy.scanModeFor("sni_scan"))
        assertNull(TargetPickPolicy.scanModeFor("sni_method_scan"))
        assertNull(TargetPickPolicy.scanModeFor("proxy_scan"))
    }

    @Test
    fun mapsModesToPinKinds() {
        assertEquals(PinKind.Sni, TargetPickPolicy.pinKindForMode("sni_spoof"))
        assertEquals(PinKind.Ip, TargetPickPolicy.pinKindForMode("ip_bypass"))
        assertEquals(PinKind.Ip, TargetPickPolicy.pinKindForMode("ip_bypass_plus"))
        assertNull(TargetPickPolicy.pinKindForMode("ip_scan"))
    }

    private fun sniPin() = TargetPin(PinKind.Sni, "edge.example.com", "1.2.3.4", 95, 1L)
    private fun ipPin() = TargetPin(PinKind.Ip, null, "5.6.7.8", 96, 1L)

    @Test
    fun gateEligibilityRequiresAutoSelectOffAndNoManualSelection() {
        assertTrue(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = false, "", "", null))
        assertFalse(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = true, "", "", null))
        assertFalse(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = false, "manual.example", "", null))
        assertFalse(TargetPickPolicy.isGateEligible("ip_bypass", autoSelect = false, "", "1.2.3.4", null))
        assertFalse(TargetPickPolicy.isGateEligible("sni_scan", autoSelect = false, "", "", null))
    }

    @Test
    fun gateEligibilityIgnoresMismatchedPinKind() {
        assertFalse(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = false, "", "", sniPin()))
        assertTrue(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = false, "", "", ipPin()))
        assertFalse(TargetPickPolicy.isGateEligible("ip_bypass", autoSelect = false, "", "", ipPin()))
        assertTrue(TargetPickPolicy.isGateEligible("ip_bypass", autoSelect = false, "", "", sniPin()))
    }
}
```

- [ ] **Step 2: Run the unit tests to verify they fail**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.targetscan.ScanResultParserTest" --tests "dev.zerodpi.android.targetscan.TargetPickPolicyTest"`
Expected: compilation fails — types unresolved.

- [ ] **Step 3: Implement the models, parser, and policy**

Create `android/app/src/main/java/dev/zerodpi/android/targetscan/ScanResultModels.kt`:

```kotlin
package dev.zerodpi.android.targetscan

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SniScanEntryModel(
    val sni: String,
    val ip: String,
    @SerialName("tcp_latency_ms") val tcpLatencyMs: Long? = null,
    @SerialName("tls_ok") val tlsOk: Boolean = false,
    @SerialName("tls_latency_ms") val tlsLatencyMs: Long? = null,
    @SerialName("cert_valid") val certValid: Boolean = false,
    @SerialName("ttfb_ms") val ttfbMs: Long? = null,
    @SerialName("http_status") val httpStatus: Int? = null,
    val score: Int = 0,
)

@Serializable
data class IpScanEntryModel(
    val ip: String,
    @SerialName("tcp_latency_ms") val tcpLatencyMs: Long? = null,
    @SerialName("tls_ok") val tlsOk: Boolean = false,
    @SerialName("tls_latency_ms") val tlsLatencyMs: Long? = null,
    @SerialName("cert_valid") val certValid: Boolean = false,
    @SerialName("ttfb_ms") val ttfbMs: Long? = null,
    @SerialName("http_status") val httpStatus: Int? = null,
    val score: Int = 0,
)
```

Create `android/app/src/main/java/dev/zerodpi/android/targetscan/ScanResultParser.kt`:

```kotlin
package dev.zerodpi.android.targetscan

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

object ScanResultParser {
    private val json = Json { ignoreUnknownKeys = true }

    fun parseSni(text: String): List<SniScanEntryModel>? =
        runCatching {
            json.decodeFromString(ListSerializer(SniScanEntryModel.serializer()), text)
        }.getOrNull()

    fun parseIp(text: String): List<IpScanEntryModel>? =
        runCatching {
            json.decodeFromString(ListSerializer(IpScanEntryModel.serializer()), text)
        }.getOrNull()
}
```

Create `android/app/src/main/java/dev/zerodpi/android/targetscan/TargetPickPolicy.kt`:

```kotlin
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
```

- [ ] **Step 4: Run the unit tests to verify they pass**

Run: `cd android && ./gradlew.bat testDebugUnitTest --tests "dev.zerodpi.android.targetscan.ScanResultParserTest" --tests "dev.zerodpi.android.targetscan.TargetPickPolicyTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/targetscan/ScanResultModels.kt android/app/src/main/java/dev/zerodpi/android/targetscan/ScanResultParser.kt android/app/src/main/java/dev/zerodpi/android/targetscan/TargetPickPolicy.kt android/app/src/test/java/dev/zerodpi/android/targetscan/ScanResultParserTest.kt android/app/src/test/java/dev/zerodpi/android/targetscan/TargetPickPolicyTest.kt
git commit -m "feat(android): add scan result models, parser, and target pick policy"
```

---

### Task 3: RuntimeStorage ephemeral run configs, pin injection, pick results IO

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/storage/RuntimeStorage.kt` (`prepareRunConfig`, add `readPickScanResults`, `deletePickScanResults`)
- Test: `android/app/src/androidTest/java/dev/zerodpi/android/storage/RuntimeStorageInstrumentedTest.kt` (append cases)

**Interfaces:**
- Consumes: `TargetPin`, `PinKind`, `TargetPickPolicy`, `TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME` (Tasks 1–2).
- Produces (used by Tasks 4–8): extended `prepareRunConfig(profileId, modeOverride, patchFields, pin)` returning `RuntimeRunConfig` whose `configFile` is an ephemeral file when `modeOverride != null || patchFields.isNotEmpty() || pin != null`; `readPickScanResults`, `deletePickScanResults`.

- [ ] **Step 1: Write the failing instrumented tests**

Append to `android/app/src/androidTest/java/dev/zerodpi/android/storage/RuntimeStorageInstrumentedTest.kt` (reuse its existing `@Before` setup and helpers; if it has none of `clearRuntimeDir`-style helpers, follow the class's existing setup and add what these tests need):

```kotlin
    @Test
    fun pickScanConfigPatchesModeAndScanOutputIntoEphemeralFile() = runBlocking {
        val storage = runtimeStorage()
        val files = storage.ensureInitialized(DEFAULT_PROFILE_ID)
        val stored = files.configFile.readText(StandardCharsets.UTF_8)
        val run = storage.prepareRunConfig(
            profileId = DEFAULT_PROFILE_ID,
            modeOverride = "sni_scan",
            patchFields = mapOf("SCAN_OUTPUT" to "pick_scan_results.json"),
        )
        assertTrue(run.configFile.name.startsWith(".sni_scan_config.toml"))
        assertTrue(run.configText.contains("MODE = \"sni_scan\""))
        assertTrue(run.configText.contains("SCAN_OUTPUT = \"pick_scan_results.json\""))
        // The user's config file is untouched.
        assertEquals(stored, files.configFile.readText(StandardCharsets.UTF_8))
    }

    @Test
    fun pinInjectionAddsSelectedSniAndSkipsScanOverrides() = runBlocking {
        val storage = runtimeStorage()
        val assignment = Regex("(?m)^\\s*SELECTED_SNI\\s*=")
        val pin = TargetPin(PinKind.Sni, "edge.example.com", "1.2.3.4", 95, 1L)
        val plain = storage.prepareRunConfig(profileId = DEFAULT_PROFILE_ID)
        assertFalse(assignment.containsMatchIn(plain.configText))
        // modeOverride runs never inject a pin.
        val scanRun = storage.prepareRunConfig(
            profileId = DEFAULT_PROFILE_ID, modeOverride = "sni_scan", pin = pin,
        )
        assertFalse(assignment.containsMatchIn(scanRun.configText))
        // Real run with matching pin -> ephemeral config with SELECTED_SNI.
        val pinned = storage.prepareRunConfig(profileId = DEFAULT_PROFILE_ID, pin = pin)
        assertTrue(pinned.configFile.name == ".run_config.toml")
        assertTrue(pinned.configText.contains("SELECTED_SNI = \"edge.example.com\""))
        // Real run with mismatched kind -> no injection.
        val ipPin = TargetPin(PinKind.Ip, null, "5.6.7.8", 96, 1L)
        val mismatched = storage.prepareRunConfig(profileId = DEFAULT_PROFILE_ID, pin = ipPin)
        assertFalse(assignment.containsMatchIn(mismatched.configText))
    }

    @Test
    fun pinInjectionDefersToManualSelectedSni() = runBlocking {
        val storage = runtimeStorage()
        val manual = ZeroDpiConfigToml.replaceOrAppendField(
            runtimeStorage().readAll(DEFAULT_PROFILE_ID).configText, "SELECTED_SNI", "manual.example",
        )
        runtimeStorage().save(DEFAULT_PROFILE_ID, RuntimeFileKind.Config, manual)
        val pin = TargetPin(PinKind.Sni, "edge.example.com", "1.2.3.4", 95, 1L)
        val run = runtimeStorage().prepareRunConfig(profileId = DEFAULT_PROFILE_ID, pin = pin)
        assertTrue(run.configText.contains("SELECTED_SNI = \"manual.example\""))
        assertFalse(run.configText.contains("edge.example.com"))
    }

    @Test
    fun pinInjectionDefersToManualSelectedSni() = runBlocking {
        val storage = runtimeStorage()
        val manual = ZeroDpiConfigToml.replaceOrAppendField(
            runtimeStorage().readAll(DEFAULT_PROFILE_ID).configText, "SELECTED_SNI", "manual.example",
        )
        runtimeStorage().save(DEFAULT_PROFILE_ID, RuntimeFileKind.Config, manual)
        val pin = TargetPin(PinKind.Sni, "edge.example.com", "1.2.3.4", 95, 1L)
        val run = runtimeStorage().prepareRunConfig(profileId = DEFAULT_PROFILE_ID, pin = pin)
        assertTrue(run.configText.contains("SELECTED_SNI = \"manual.example\""))
        assertFalse(run.configText.contains("edge.example.com"))
    }

    @Test
    fun pickScanResultsWriteReadDeleteLifecycle() = runBlocking {
        val storage = runtimeStorage()
        val profileId = DEFAULT_PROFILE_ID
        storage.deletePickScanResults(profileId)
        assertEquals(null, storage.readPickScanResults(profileId))
        val files = storage.ensureInitialized(profileId)
        val resultsFile = File(files.runtimeDir, TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME)
        resultsFile.writeText("[]")
        assertEquals("[]", storage.readPickScanResults(profileId))
        storage.deletePickScanResults(profileId)
        assertEquals(null, storage.readPickScanResults(profileId))
    }
```

Imports to add at the top of the test file: `dev.zerodpi.android.targetscan.PinKind`, `dev.zerodpi.android.targetscan.TargetPin`, `dev.zerodpi.android.targetscan.TargetScanFiles`, `java.io.File`, `java.nio.charset.StandardCharsets` (as needed). Also confirm the test class's existing helpers: adjust `runtimeStorage()` and `DEFAULT_PROFILE_ID` to whatever the class already uses (e.g., an `application`/`context` field and `ZeroDpiProfile.DEFAULT_PROFILE_ID`).

- [ ] **Step 2: Run the instrumented tests to verify they fail**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest`
Expected: the new tests fail to compile (missing `patchFields`/`pin` parameters, missing `readPickScanResults`).

- [ ] **Step 3: Implement the RuntimeStorage changes**

In `RuntimeStorage.kt`:

1. Add imports: `dev.zerodpi.android.targetscan.PinKind`, `dev.zerodpi.android.targetscan.TargetPin`, `dev.zerodpi.android.targetscan.TargetPickPolicy`, `dev.zerodpi.android.targetscan.TargetScanFiles`.

2. Replace the body of `prepareRunConfig` (keep the signature defaulted so existing callers compile):

```kotlin
    suspend fun prepareRunConfig(
        profileId: String,
        modeOverride: String? = null,
        patchFields: Map<String, String> = emptyMap(),
        pin: TargetPin? = null,
    ): RuntimeRunConfig =
        withContext(Dispatchers.IO) {
            val currentFiles = ensureInitializedForProfile(profileId)
            val storedConfigText = currentFiles.configFile.readText(StandardCharsets.UTF_8)
            val withMode = modeOverride?.let { mode ->
                ZeroDpiConfigToml.replaceOrAppendField(
                    text = storedConfigText,
                    fieldName = "MODE",
                    value = mode,
                )
            } ?: storedConfigText
            val withPatches = patchFields.entries.fold(withMode) { text, (fieldName, value) ->
                ZeroDpiConfigToml.replaceOrAppendField(
                    text = text,
                    fieldName = fieldName,
                    value = value,
                )
            }
            val runConfigText = withPatches.injectPin(pin)

            val ephemeral = modeOverride != null || patchFields.isNotEmpty() || pin != null
            val runConfigFile = if (ephemeral) {
                val name = modeOverride?.let { ".${it}_config.toml" } ?: ".run_config.toml"
                File(currentFiles.runtimeDir, name).also { target ->
                    RuntimeFileOps.atomicWrite(target = target, content = runConfigText, backup = null)
                }
            } else {
                currentFiles.configFile
            }

            val resolvedPaths = resolveConfigPaths(runConfigText, currentFiles.runtimeDir)
            resolvedPaths.scanOutput?.parentFile?.let(RuntimeFileOps::ensureDirectory)
            resolvedPaths.methodScanOutput?.parentFile?.let(RuntimeFileOps::ensureDirectory)

            RuntimeRunConfig(
                files = currentFiles,
                configFile = runConfigFile,
                configText = runConfigText,
                modeOverride = modeOverride,
            )
        }
```

3. Add the private `injectPin` helper on `RuntimeStorage` (top-level function in the same file so it is unit-testable is also fine; a private member is preferred to keep the file cohesive):

```kotlin
    private fun String.injectPin(pin: TargetPin?): String {
        if (pin == null) {
            return this
        }
        val mode = readTomlString(this, "MODE") ?: "sni_spoof"
        val expectedKind = TargetPickPolicy.pinKindForMode(mode) ?: return this
        if (pin.kind != expectedKind) {
            return this
        }
        val fieldName = when (expectedKind) {
            PinKind.Sni -> "SELECTED_SNI"
            PinKind.Ip -> "SELECTED_IP"
        }
        // A manual SELECTED_* in the user's config wins over the app pin.
        if (!readTomlString(this, fieldName).isNullOrBlank()) {
            return this
        }
        val value = when (expectedKind) {
            PinKind.Sni -> pin.sni ?: return this
            PinKind.Ip -> pin.ip
        }
        return ZeroDpiConfigToml.replaceOrAppendField(text = this, fieldName = fieldName, value = value)
    }
```

4. Add the pick-results functions next to `readMethodScanOutput`:

```kotlin
    suspend fun readPickScanResults(profileId: String): String? =
        withContext(Dispatchers.IO) {
            pickScanResultsFile(profileId)
                .takeIf { it.isFile }
                ?.readText(StandardCharsets.UTF_8)
        }

    suspend fun deletePickScanResults(profileId: String) =
        withContext(Dispatchers.IO) {
            pickScanResultsFile(profileId).delete()
        }

    private suspend fun pickScanResultsFile(profileId: String): File {
        val currentFiles = ensureInitializedForProfile(profileId)
        return File(currentFiles.runtimeDir, TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME)
    }
```

- [ ] **Step 4: Run the instrumented tests to verify they pass**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest`
Expected: all new RuntimeStorage cases PASS; existing tests green.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/storage/RuntimeStorage.kt android/app/src/androidTest/java/dev/zerodpi/android/storage/RuntimeStorageInstrumentedTest.kt
git commit -m "feat(android): add ephemeral run config pin injection and pick scan results IO"
```

---

### Task 4: Choosing runtime status plumbing

Adding a `RuntimeStatus` enum member breaks exhaustive `when`s; this task lands the enum + state field + every mechanical consumer in one compiling commit.

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt` (`RuntimeStatus`, state types, `activeStatuses`/`networkRestartableStatuses`)
- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/HomeScreen.kt` (`statusLabel`, `RuntimeStatusCard`)
- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/UiComponents.kt` (`RuntimeStatus.isTransient`)
- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/MainViewModel.kt` (status-set `when` blocks at ~1175–1240)
- Modify: `android/app/src/main/res/values/strings.xml`
- Test: `android/app/src/androidTest/java/dev/zerodpi/android/ui/DashboardScreenTest.kt` (append one label assertion)

**Interfaces:**
- Consumes: nothing new.
- Produces (Tasks 5–7 use): `RuntimeStatus.Choosing`, `PickPhase`, `PickOrigin`, `PickSessionUi`, `ZeroDpiServiceState.pickSession`.

- [ ] **Step 1: Add the types and state field**

In `ZeroDpiService.kt`:

1. Add `Choosing` to the `RuntimeStatus` enum (between `Restarting` and `Stopping` keeps ordering tidy):

```kotlin
enum class RuntimeStatus {
    Stopped,
    Starting,
    Scanning,
    Running,
    Restarting,
    Choosing,
    Stopping,
    Failed,
}
```

2. Add the pick-session types near `ScanProgressInfo`:

```kotlin
enum class PickPhase { Scanning, Choosing }

enum class PickOrigin { StartGate, MidRun, Standalone }

data class PickSessionUi(
    val phase: PickPhase,
    val origin: PickOrigin,
    val mode: String,
    val resumeAvailable: Boolean,
)
```

3. Add the field to `ZeroDpiServiceState`:

```kotlin
    val pickSession: PickSessionUi? = null,
```

4. In the companion object, extend the two sets:

```kotlin
        private val activeStatuses = setOf(
            RuntimeStatus.Starting,
            RuntimeStatus.Scanning,
            RuntimeStatus.Running,
            RuntimeStatus.Restarting,
            RuntimeStatus.Choosing,
            RuntimeStatus.Stopping,
        )
        // networkRestartableStatuses intentionally does NOT include Choosing:
        // a network change during a pick session must not race the session.
```

- [ ] **Step 2: Fix the exhaustive consumers**

In `HomeScreen.kt`:

- `statusLabel`: add `RuntimeStatus.Choosing -> R.string.status_choosing` (label added in Step 3).
- `RuntimeStatusCard`: add `RuntimeStatus.Choosing` to the `RuntimeStatus.Starting, ...` branch that shows the Stop `OutlinedButton` — while Choosing, Stop means cancel the pick session (the service treats a stop during a session as cancel-and-abort).

In `UiComponents.kt` `RuntimeStatus.isTransient()` (around line 322): leave `Choosing` out (no indeterminate progress bar while the picker is displayed).

In `MainViewModel.kt` (status sets used for transient/active checks around lines 1175–1240): read each `when`/`in setOf(...)` block that enumerates statuses and add `RuntimeStatus.Choosing` wherever `RuntimeStatus.Scanning` appears, EXCEPT the method-scan card state machine (`updateMethodScanState`), which must treat `Choosing` as a terminal (non-transient) status so the method card does not misbehave — inspect each block and make the minimal correct change; the compile errors will point at every site that needs a decision.

- [ ] **Step 3: Add the string**

In `android/app/src/main/res/values/strings.xml`, next to `status_restarting`:

```xml
    <string name="status_choosing">Choosing target</string>
```

- [ ] **Step 4: Add the label test**

Append to `DashboardScreenTest.kt` a test that renders the dashboard with a service state whose status is `Choosing` and asserts the label text appears (follow the file's existing harness — it renders `DashboardScreen` with fake states; mirror an existing status test such as the `Restarting` one, changing the status and expected string to `Choosing`/`Choosing target`).

- [ ] **Step 5: Run tests and verify compilation**

Run: `cd android && ./gradlew.bat compileDebugKotlin` then the unit suite `./gradlew.bat testDebugUnitTest`, then `./gradlew.bat connectedDebugAndroidTest` scoped to DashboardScreenTest:
`./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.ui.DashboardScreenTest`
Expected: everything compiles and passes.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt android/app/src/main/java/dev/zerodpi/android/ui/HomeScreen.kt android/app/src/main/java/dev/zerodpi/android/ui/UiComponents.kt android/app/src/main/java/dev/zerodpi/android/ui/MainViewModel.kt android/app/src/main/res/values/strings.xml android/app/src/androidTest/java/dev/zerodpi/android/ui/DashboardScreenTest.kt
git commit -m "feat(android): add Choosing runtime status for target pick sessions"
```

---

### Task 5: Service pick-session orchestration

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt`
- Modify: `android/app/src/main/java/dev/zerodpi/android/runtime/FakeZeroDpiRunner.kt` (write scan-results JSON so fake-mode scans exercise the real app path)
- Test: `android/app/src/androidTest/java/dev/zerodpi/android/service/TargetPickServiceInstrumentedTest.kt` (create)

**Interfaces:**
- Consumes: `RuntimeStatus.Choosing`, `PickPhase`, `PickOrigin`, `PickSessionUi`, `ZeroDpiServiceState.pickSession` (Task 4); `TargetPickPolicy`, `TargetScanFiles` (Task 2); `TargetPinStore`, `prepareRunConfig(patchFields=…, pin=…)`, `readPickScanResults`, `deletePickScanResults` (Tasks 1, 3).
- Produces (Task 6 uses): `ZeroDpiService.requestTargetPick()`, `applyTargetPick()`, `cancelTargetPick()`; the service-state transitions described in the step table below.

**Service state machine (normative).** Internal field:

```kotlin
private data class PickSession(
    val profileId: String,
    val origin: PickOrigin,
    val resumeRunSpec: ActiveRunSpec?,
)
private enum class PickStage { StoppingForRescan, Scanning, Choosing }
private var pickSession: PickSession? = null
private var pickStage: PickStage? = null
private var pickScanMode: String? = null        // "sni_scan" | "ip_scan" for pickSession.mode
private var pickCancelRequested = false
```

Transitions (all in `handleRunnerEvent`/orchestration helpers):

| # | Event / call | Condition | Action |
|---|---|---|---|
| 1 | `startZeroDpi` → gate check in `launchRun` | editor: mode pickable, `AUTO_SELECT=false`, `SELECTED_*` blank for kind; `pinStore.read(profileId)` returns null or mismatched kind | Start **pick scan** instead of the run: `pickSession = PickSession(profileId, StartGate, resumeRunSpec = null)`; `launchPickScan(session)` (which sets `pickStage = Scanning`); return — the run never starts |
| 2 | `requestTargetPick(profileId)` | status Running/Starting/Scanning/Restarting | store `PickSession(profileId, MidRun, resumeRunSpec = activeRunSpec)`; stop network monitor; state → `Restarting` with `pickSession = PickSessionUi(Scanning, MidRun, "", resumeAvailable = true)`; `pickStage = StoppingForRescan`; log "Stopping to scan for a new target."; `scope.launch { runner.stop() }` — the Exited handler (row 10) launches the scan |
| 3 | `requestTargetPick(profileId)` | status Stopped/Failed | `PickSession(profileId, Standalone, resumeRunSpec = null)`; `ensureForeground()`; `pickStage = Scanning`; `launchPickScan(session)` immediately |
| 4 | pick scan run exits 0 | `pickStage == Scanning`, not cancelled, not user stop | `pickStage = Choosing`; state: `status = Choosing`, `pickSession = PickSessionUi(Choosing, origin, pickScanMode, resumeAvailable = resumeRunSpec != null)`; do NOT call `finishAfterExit`; log "Scan finished — choose a target." |
| 5 | pick scan exits non-zero | `pickStage == Scanning` | `failPickSession(message)`; MidRun → relaunch `resumeRunSpec`; StartGate/Standalone → `finishForegroundRun()` with `lastError`; clear session |
| 6 | `applyTargetPick()` | `pickStage == Choosing` | clear session; then: origin StartGate → internal start of a normal run for `profileId` (state back to Stopped first, then `startZeroDpi(profileId)`); MidRun → `launchRun(resumeRunSpec!!, isAutomaticRestart = true)`; Standalone → log "Target pinned; start ZeroDPI when ready." and `finishForegroundRun()` |
| 7 | `cancelTargetPick()` | `pickStage == Choosing` | same as 6 but with session cleared and NO pin written (the pin file is untouched); log "Pick cancelled." |
| 8 | `cancelTargetPick()` | `pickStage == Scanning` | set `pickCancelRequested = true`; `runner.stop()`; the Exited handler resolves per origin (MidRun → relaunch resume; StartGate/Standalone → finish) |
| 9 | `stopZeroDpi()` | any pick stage | treat as user abort: clear session; existing stop path finishes as Stopped, no resume |
| 10 | Exited while `pickStage == StoppingForRescan` | stop completed, `exitCode == 0`, not user stop | `launchPickScan(session)` (stage → Scanning); on non-zero exit → resolve as abort (MidRun → relaunch resume; others → finish) |
| 11 | Scan config prep fails, root error, or runner fails to start | any | `failPickSession(message)` as in 5 |

`launchPickScan()` (shared by StartGate, MidRun-after-stop, Standalone):

```kotlin
private fun launchPickScan(session: PickSession) {
    scope.launch {
        // Scan kind is derived from the user config's MODE (never the scan
        // override itself): sni_spoof -> sni_scan, ip_bypass(_plus) -> ip_scan.
        val userMode = runCatching {
            ZeroDpiConfigToml.analyze(
                runtimeStorage.readAll(session.profileId).configText,
            ).valueFor("MODE")
        }.getOrDefault("sni_spoof")
        val scanMode = TargetPickPolicy.scanModeFor(userMode)
        if (scanMode == null) {
            failPickSession("MODE '$userMode' does not support target picking.")
            return@launch
        }
        pickScanMode = scanMode
        val runConfig = runCatching {
            runtimeStorage.prepareRunConfig(
                profileId = session.profileId,
                modeOverride = scanMode,
                patchFields = mapOf("SCAN_OUTPUT" to TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME),
            )
        }.getOrElse { error ->
            failPickSession(error.message ?: "Could not prepare the pick scan config.")
            return@launch
        }
        runtimeStorage.deletePickScanResults(session.profileId)
        pickStage = PickStage.Scanning
        launchRun(
            ActiveRunSpec(profileId = session.profileId, modeOverride = scanMode),
            isAutomaticRestart = false,
            preparedConfigOverride = runConfig,
        )
    }
}
```

Implementation notes for the above (mandatory):

- `prepareRunConfig` derives the ephemeral file and resolved text; `launchRun` currently re-prepares config internally from `runSpec`. To avoid double work and to pass the SCAN_OUTPUT patch, extend `launchRun(runSpec, isAutomaticRestart, preparedConfigOverride: RuntimeRunConfig? = null)`; when the override is present, skip the internal `prepareRunConfig` call and use the override for `configText`/`configFile`, but still run the rest of the existing body (editor analyze, root gating — scan modes are rootless so this is a no-op — state updates, logging, `startNetworkMonitoring()`, `runner.start`).
- The Start gate check runs inside `startZeroDpi`/`launchRun` where `runConfig.configText` is already analyzed: gate condition = `TargetPickPolicy.isGateEligible(mode, autoSelect, selectedSni, selectedIp, pin)` with `pin = pinStore.read(profileId)` and the guard `modeOverride == null && pickSession == null && !userStopRequested`; on eligible, log `"AUTO_SELECT is off — scanning; choose a target after the scan."`, set `pickSession = PickSession(runSpec.profileId, PickOrigin.StartGate, resumeRunSpec = null)`, call `launchPickScan(pickSession!!)`, and return (never start the run).
- Add `private val pinStore = TargetPinStore(this)` next to `runtimeStorage` in `onCreate`.
- MidRun sessions use the same "internal stop, not a user stop" semantics as `requestAutomaticRestart`: `userStopRequested` is NOT set. The Exited handler must route on `pickStage` *before* the existing restart/`finishAfterExit` logic:

```kotlin
is ZeroDpiRunnerEvent.Exited -> {
    appendLog("ZeroDPI exited with code ${event.exitCode}.")
    activeConnections.clear()
    activeRelayBytes.clear()
    when {
        pickStage == PickStage.StoppingForRescan && !userStopRequested -> {
            if (event.exitCode == 0) {
                val session = pickSession
                if (session != null) {
                    launchPickScan(session) // sets pickStage = Scanning
                } else {
                    finishAfterExit(event.exitCode)
                }
            } else {
                appendLog("Could not stop the running ZeroDPI for a target pick.")
                resolvePickSession(startAfterPick = false)
            }
        }
        pickStage == PickStage.Scanning && event.exitCode == 0 && !pickCancelRequested && !userStopRequested -> {
            pickStage = PickStage.Choosing
            state.update {
                it.copy(
                    status = RuntimeStatus.Choosing,
                    pickSession = PickSessionUi(
                        phase = PickPhase.Choosing,
                        origin = pickSession?.origin ?: PickOrigin.Standalone,
                        mode = pickScanMode.orEmpty(),
                        resumeAvailable = pickSession?.resumeRunSpec != null,
                    ),
                    scanProgress = null,
                    activeTarget = "Choose a target",
                    activeTargetScore = null,
                )
            }
            appendLog("Scan finished — choose a target from the picker.")
        }
        pickStage == PickStage.Scanning && (pickCancelRequested || userStopRequested) -> {
            val session = pickSession
            clearPickSession()
            if (pickCancelRequested && !userStopRequested && session?.origin == PickOrigin.MidRun) {
                appendLog("Target pick cancelled — resuming the previous run.")
                launchRun(session.resumeRunSpec!!, isAutomaticRestart = true)
            } else {
                finishAfterExit(event.exitCode)
            }
        }
        else -> { /* existing Exited handling (restart machinery / finishAfterExit) */ }
    }
}
```

Note: `StoppingForRescan` + `userStopRequested` and `StoppingForRescan` + `exitCode != 0` fall into the `else` branch via `clearPickSession()` in `stopZeroDpi`/`finishAfterExit` (rows 9–10), which resets `pickStage` to null before the existing logic runs.

Note: with the `launchRun(preparedConfigOverride)` approach, the pick scan is a normal run and its `ScanStarted`/`ScanProgress`/`ScanCompleted` events already drive `RuntimeStatus.Scanning` + `scanProgress` in the UI. `launchRun`'s start also calls `startNetworkMonitoring()`; the monitor is stopped again whenever a session ends or a MidRun shutdown starts (see notes above), so network-change restarts can never collide with a session.

- `applyTargetPick`/`cancelTargetPick`/`failPickSession` all funnel into:

```kotlin
private fun resolvePickSession(startAfterPick: Boolean) {
    val session = pickSession ?: return
    val resume = pickResumeRunSpec
    clearPickSession()
    when (session.origin) {
        PickOrigin.MidRun -> if (resume != null && !userStopRequested) {
            launchRun(resume, isAutomaticRestart = true)
        } else {
            finishForegroundRun()
        }
        PickOrigin.StartGate -> if (startAfterPick && !userStopRequested) {
            state.update { it.copy(status = RuntimeStatus.Stopped, pickSession = null) }
            startZeroDpi(profileId = session.profileId)
        } else {
            finishForegroundRun()
        }
        PickOrigin.Standalone -> finishForegroundRun()
    }
}
```

`cancelTargetPick()` → if `pickStage == Choosing`: `resolvePickSession(startAfterPick = false)` with log "Target pick cancelled."; if `pickStage == Scanning`: `pickCancelRequested = true; runner.stop()` (Exited branch handles resolution).
`applyTargetPick()` → only valid in `Choosing`: the pin was already written by the ViewModel; `resolvePickSession(startAfterPick = true)` with log "Target pinned. Applying selection."

- Add `clearPickSession()` resetting `pickSession`, `pickStage`, `pickScanMode`, `pickCancelRequested` and updating `state.pickSession = null`; call it from `finishForegroundRun()`, `finishAfterExit()`, `stopZeroDpi()`, `forceStopZeroDpi()`, and at `startZeroDpi()` entry.


- [ ] **Step 1: Write the failing instrumented tests**

Create `android/app/src/androidTest/java/dev/zerodpi/android/service/TargetPickServiceInstrumentedTest.kt`. It needs its own binding helpers because the existing ones are private to `ZeroDpiServiceInstrumentedTest` — copy the minimal versions (they use `ServiceTestRule`, `bindService`, and a `waitForState` polling loop; mirror the existing file's implementations, which are short):

```kotlin
package dev.zerodpi.android.service

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.storage.RuntimeStorage
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.TargetPin
import dev.zerodpi.android.targetscan.TargetPinCodec
import dev.zerodpi.android.targetscan.TargetScanFiles
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class TargetPickServiceInstrumentedTest {
    @get:Rule
    val serviceRule = ServiceTestRule()

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        runBlocking { clearRuntimeState() }
    }

    @Test
    fun startGateRunsPickScanThenApplyingPickStartsPinnedRun() = runBlocking {
        val storage = RuntimeStorage(context)
        val config = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText
            .let { ZeroDpiConfigToml.replaceOrAppendField(it, "AUTO_SELECT", "false") }
        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, config)
        val service = bindZeroDpiService()

        service.startZeroDpi() // gate fires: scan, not run


        // Scan events arrive (fake runner emits sni_scan flow), then Choosing.
        val choosing = service.waitForState { it.status == RuntimeStatus.Choosing }
        assertEquals(PickOrigin.StartGate, choosing.pickSession?.origin)
        assertEquals("sni_scan", choosing.pickSession?.mode)

        // Simulate the ViewModel pinning the picked target, then apply.
        val pinFile = pinFile(storage)
        pinFile.writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L)),
        )
        service.applyTargetPick()

        val running = service.waitForState { it.status == RuntimeStatus.Running }
        assertEquals(null, running.pickSession)
        assertTrue(running.recentLogs.any { it.contains("Selected sni target cloudflare.com") })
    }

    @Test
    fun cancelFromStartGateStopsWithoutStarting() = runBlocking {
        val storage = RuntimeStorage(context)
        storage.save(
            ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config,
            ZeroDpiConfigToml.replaceOrAppendField(
                storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText,
                "AUTO_SELECT", "false",
            ),
        )
        val service = bindZeroDpiService()
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Choosing }

        service.cancelTargetPick()

        val stopped = service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
        assertEquals(null, stopped.pickSession)
    }

    @Test
    fun midRunRescanStopsScansAndRelaunchesAfterPick() = runBlocking {
        val storage = RuntimeStorage(context)
        val config = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText
            .let { ZeroDpiConfigToml.replaceOrAppendField(it, "AUTO_SELECT", "false") }
        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, config)
        val service = bindZeroDpiService()
        // Seed a pin so the initial start runs directly.
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L)),
        )
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Running }

        service.requestTargetPick(ZeroDpiProfile.DEFAULT_PROFILE_ID) // MidRun origin

        service.waitForState { it.status == RuntimeStatus.Choosing }
        // Replace the pin with a different target, then apply -> relaunch.
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "speed.cloudflare.com", "1.1.1.1", 98, 2L)),
        )
        service.applyTargetPick()

        val running = service.waitForState { it.status == RuntimeStatus.Running }
        assertTrue(running.recentLogs.any { it.contains("Relaunching ZeroDPI") })
        assertEquals(null, running.pickSession)
    }

    @Test
    fun cancelMidRunRescanRelaunchesPreviousRun() = runBlocking {
        val storage = RuntimeStorage(context)
        storage.save(
            ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config,
            ZeroDpiConfigToml.replaceOrAppendField(
                storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText, "AUTO_SELECT", "false",
            ),
        )
        val service = bindZeroDpiService()
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L)),
        )
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Running }

        service.requestTargetPick(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        service.waitForState { it.status == RuntimeStatus.Choosing }

        service.cancelTargetPick()

        service.waitForState { it.status == RuntimeStatus.Running }
    }

    @Test
    fun standalonePickFromStoppedEndsStoppedAfterApply() = runBlocking {
        val storage = RuntimeStorage(context)
        val service = bindZeroDpiService()
        service.requestTargetPick(ZeroDpiProfile.DEFAULT_PROFILE_ID) // stopped -> Standalone
        service.waitForState { it.status == RuntimeStatus.Choosing }
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Ip, null, "104.16.132.229", 96, 3L)),
        )
        service.applyTargetPick()
        val stopped = service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
        assertEquals(null, stopped.pickSession)
    }

    // ---- helpers (mirror ZeroDpiServiceInstrumentedTest) ----

    private suspend fun clearRuntimeState() {
        val storage = RuntimeStorage(context)
        val repositoryFiles = storage.ensureInitialized(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        File(repositoryFiles.runtimeDir, TargetScanFiles.PIN_FILE_NAME).delete()
        storage.deletePickScanResults(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        storage.clearLogs()
    }

    // Note: ServiceTestRule tears the bound service down between tests; the
    // state it leaves is reset by the next test's own setup above.


    private suspend fun pinFile(storage: RuntimeStorage): File {
        val files = storage.ensureInitialized(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        return File(files.runtimeDir, TargetScanFiles.PIN_FILE_NAME)
    }

    private fun bindZeroDpiService(): ZeroDpiService {
        val latch = CountDownLatch(1)
        var bound: ZeroDpiService? = null
        context.bindService(
            Intent(context, ZeroDpiService::class.java),
            object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                    bound = (binder as ZeroDpiService.LocalBinder).service()
                    latch.countDown()
                }

                override fun onServiceDisconnected(name: ComponentName?) = Unit
            },
            Context.BIND_AUTO_CREATE,
        )
        latch.await(10, TimeUnit.SECONDS)
        return bound!!
    }

    private fun ZeroDpiService.waitForState(
        timeoutMs: Long = 15_000L,
        condition: (ZeroDpiServiceState) -> Boolean,
    ): ZeroDpiServiceState {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val state = state().value
            if (condition(state)) {
                return state
            }
            Thread.sleep(50)
        }
        throw AssertionError("Timed out waiting for service state; last: ${state().value}")
    }
}
```

Before writing these, verify the fake runner's sni_scan flow logs (`Selected sni target …` comes from the real binary's `SelectedTarget` event text "Selected sni target …" — the fake emits `ZeroDpiRunnerEvent.SelectedTarget` and the service logs `"Selected ${event.target} target …"`; adjust the log assertions to the actual wording, e.g. `contains("Selected sni target")`; the fake's run-mode flow does emit `SelectedTarget` then `ListenerStarted`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.service.TargetPickServiceInstrumentedTest`
Expected: compilation fails — `requestTargetPick`/`applyTargetPick`/`cancelTargetPick` unresolved, `Choosing` missing from the state machine.

- [ ] **Step 3: Implement the service orchestration**

Follow the state machine and code above. Concretely in `ZeroDpiService.kt`:

1. Add the private fields, `PickSession` data class and `PickStage` enum (top of class).
2. `onCreate`: add `pinStore = TargetPinStore(this)`.
3. Add the gate check at the top of the run-launch path: after `prepareRunConfig` and `ZeroDpiConfigToml.analyze(runConfig.configText)` inside `launchRun`, before root gating, when `modeOverride == null && pickSession == null` and the config is gate-eligible (mode from `editorState.valueFor("MODE")`, `AUTO_SELECT` equals "false", `SELECTED_SNI`/`SELECTED_IP` blank for kind, `pinStore.read(profileId)` mismatched-or-null) → begin a StartGate session and launch the pick scan, then return. Keep `state.status` untouched by this check until `launchPickScan` runs (its `launchRun` call drives Starting/Scanning through events).
4. `launchRun` gains `preparedConfigOverride: RuntimeRunConfig? = null` (see notes).
5. Add `requestTargetPick(profileId: String)` (origin decided by current status), `applyTargetPick()`, `cancelTargetPick()`, `launchPickScan`, `resolvePickSession`, `failPickSession`, `clearPickSession`, and the Exited-branch routing per the table:

```kotlin
fun requestTargetPick(profileId: String) {
    val currentStatus = state.value.status
    when {
        pickSession != null || restartStopInProgress -> {
            appendLog("A target pick session is already in progress.")
        }
        currentStatus in networkRestartableStatuses -> {
            val resume = activeRunSpec ?: run {
                appendLog("Cannot re-scan: no active run to resume.")
                return
            }
            networkMonitor?.stop()
            pickSession = PickSession(profileId, PickOrigin.MidRun, resume)
            pickStage = PickStage.StoppingForRescan
            state.update {
                it.copy(
                    status = RuntimeStatus.Restarting,
                    pickSession = PickSessionUi(PickPhase.Scanning, PickOrigin.MidRun, "", resumeAvailable = true),
                    scanProgress = null,
                )
            }
            appendLog("Stopping to scan for a new target.")
            scope.launch { runner.stop() }
        }
        currentStatus == RuntimeStatus.Stopped || currentStatus == RuntimeStatus.Failed -> {
            ensureForeground()
            pickSession = PickSession(profileId, PickOrigin.Standalone, null)
            launchPickScan(pickSession!!)
        }
        else -> appendLog("Target picking is unavailable while $currentStatus.")
    }
}
```

(`launchPickScan` sets `pickStage = Scanning`; the StartGate path in `launchRun` does the same before calling it.) Wire `clearPickSession()` into `finishForegroundRun()`, `finishAfterExit()`, `stopZeroDpi()`, `forceStopZeroDpi()`, and at `startZeroDpi()` entry. `clearPickSession()` also clears `state.pickSession`.
6. Handle scan failure events: `FatalError`/`Failed` runner events while `pickStage == Scanning` → `failPickSession`.

- [ ] **Step 4: Extend FakeZeroDpiRunner to write pick scan results**

Modify `android/app/src/main/java/dev/zerodpi/android/runtime/FakeZeroDpiRunner.kt` so that when a scan-mode request finishes (`sni_scan`/`ip_scan`), it writes the results JSON the app parses, next to the config file (the ephemeral config's parent is the runtime dir; `SCAN_OUTPUT = "pick_scan_results.json"` resolves there too):

```kotlin
private fun writeScanResults(request: ZeroDpiRunRequest) {
    if (request.mode != "sni_scan" && request.mode != "ip_scan") return
    val dir = File(request.configPath).parentFile ?: return
    val results = if (request.mode == "sni_scan") {
        """
        [
          {"sni": "cloudflare.com", "ip": "1.1.1.1", "tcp_latency_ms": 35, "tls_ok": true,
           "tls_latency_ms": 60, "cert_valid": true, "ttfb_ms": 90, "download_bps": 1048576.0,
           "upload_bps": 786432.0, "speed_bps": 1048576.0, "http_status": 200, "score": 95},
          {"sni": "unreachable.example", "ip": "10.0.0.1", "tcp_latency_ms": null, "tls_ok": false,
           "tls_latency_ms": null, "cert_valid": false, "ttfb_ms": null, "download_bps": null,
           "upload_bps": null, "speed_bps": null, "http_status": null, "score": 0}
        ]
        """.trimIndent()
    } else {
        """
        [
          {"ip": "104.16.132.229", "tcp_latency_ms": 30, "tls_ok": true, "tls_latency_ms": 55,
           "cert_valid": true, "ttfb_ms": 80, "download_bps": 2048000.0, "upload_bps": 1048576.0,
           "speed_bps": 2048000.0, "http_status": 200, "score": 96}
        ]
        """.trimIndent()
    }
    File(dir, TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME).writeText(results)
}
```

Call `writeScanResults(request)` right after emitting `ScanCompleted` and before `Exited(0)` in the scan branch. Add imports `java.io.File`, `dev.zerodpi.android.targetscan.TargetScanFiles`.

- [ ] **Step 5: Run the instrumented tests**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.service.TargetPickServiceInstrumentedTest`
Expected: all five cases PASS (iterate on log-text assertions until they match the service's actual log lines).

- [ ] **Step 6: Run the full service test class to check for regressions**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.service.ZeroDpiServiceInstrumentedTest`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt android/app/src/main/java/dev/zerodpi/android/runtime/FakeZeroDpiRunner.kt android/app/src/androidTest/java/dev/zerodpi/android/service/TargetPickServiceInstrumentedTest.kt
git commit -m "feat(android): add service pick-session orchestration for target selection"
```

---

### Task 6: MainViewModel picker state, actions, and pin-clear policy

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/MainViewModel.kt`
- Test: `android/app/src/androidTest/java/dev/zerodpi/android/ui/MainViewModelInstrumentedTest.kt` (append cases)

**Interfaces:**
- Consumes: service state `pickSession` + statuses (Tasks 4–5); `TargetPinStore`, `TargetPickPolicy`, `ScanResultParser`, models, `RuntimeStorage.readPickScanResults` (Tasks 1–3).
- Produces (Task 7 renders): `TargetPickUiState` (`phase: TargetPickPhase`, `pin: TargetPin?`, `mode: String?`, `progress: ScanProgressInfo?`, `entries: List<TargetPickEntryModel>?`, `resumeAvailable: Boolean`, `origin: PickOrigin?`), actions `requestTargetPick()`, `cancelTargetPick()`, `chooseTarget(entry)`, `clearTargetPin()`, and an internal `refreshTargetPin()`.

**State model:**

```kotlin
sealed interface TargetPickPhase {
    data object Hidden : TargetPickPhase
    data object Idle : TargetPickPhase
    data object Scanning : TargetPickPhase
    data object Choosing : TargetPickPhase
    data class Failed(val message: String) : TargetPickPhase
}

/** One selectable scan result row (kind-specific fields flattened). */
data class TargetPickEntryModel(
    val sni: String?,
    val ip: String,
    val score: Int,
    val tcpLatencyMs: Long?,
)

data class TargetPickUiState(
    val phase: TargetPickPhase = TargetPickPhase.Hidden,
    val mode: String? = null,
    val pin: TargetPin? = null,
    val progress: ScanProgressInfo? = null,
    val entries: List<TargetPickEntryModel>? = null,
    val resumeAvailable: Boolean = false,
    val origin: PickOrigin? = null,
)
```

- [ ] **Step 1: Write the failing instrumented tests**

Append to `android/app/src/androidTest/java/dev/zerodpi/android/ui/MainViewModelInstrumentedTest.kt` (reuse its private helpers: `viewModel(...)`, `waitUntilLoaded()`, `waitUntil(label) { … }`, `updateConfigField(name, value)`, `clearRuntimeDir()`; read the file first and match actual names):

```kotlin
    @Test
    fun startGateWithAutoSelectOffShowsPickerAndPickPinsAndRuns() = runBlocking {
        val viewModel = viewModel()
        viewModel.waitUntilLoaded()
        viewModel.updateConfigField("AUTO_SELECT", "false")
        viewModel.waitUntil("config saved") {
            RuntimeFileKind.Config !in runtimeFilesState.value.dirtyFiles
        }

        viewModel.start()

        viewModel.waitUntil("picker choosing") {
            targetPickState.value.phase == TargetPickPhase.Choosing
        }
        assertEquals(2, targetPickState.value.entries?.size)
        val entries = targetPickState.value.entries!!
        assertTrue(entries.any { it.score == 0 }) // failed row present but unselectable in UI

        viewModel.chooseTarget(entries.first { it.score > 0 })

        viewModel.waitUntil("running after pick") {
            uiState.value.status == RuntimeStatus.Running && uiState.value.pickSession == null
        }
        // Pin persisted app-side.
        val storage = RuntimeStorage(application)
        val pin = TargetPinStore(application).read(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        assertEquals("cloudflare.com", pin?.sni)
    }

    @Test
    fun clearTargetPinClearsStoredPin() = runBlocking {
        val viewModel = viewModel()
        viewModel.waitUntilLoaded()
        TargetPinStore(application).write(
            ZeroDpiProfile.DEFAULT_PROFILE_ID,
            TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L),
        )
        viewModel.refreshTargetPin()
        viewModel.waitUntil("pin shown") { targetPickState.value.pin?.sni == "cloudflare.com" }

        viewModel.clearTargetPin()

        viewModel.waitUntil("pin cleared") { targetPickState.value.pin == null }
    }
```

Imports to add in the test file: `dev.zerodpi.android.service.RuntimeStatus`, `dev.zerodpi.android.targetscan.*`, `dev.zerodpi.android.storage.TargetPinStore`, `ZeroDpiProfile` as needed.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.ui.MainViewModelInstrumentedTest`
Expected: compilation fails — `targetPickState`, `TargetPickPhase`, actions unresolved.

- [ ] **Step 3: Implement the ViewModel changes**

In `MainViewModel.kt`:

1. Add fields:

```kotlin
    private val _targetPickState = MutableStateFlow(TargetPickUiState())
    val targetPickState: StateFlow<TargetPickUiState> = _targetPickState.asStateFlow()
    private val pinStore = TargetPinStore(appContext)
    private var lastPickGeneration = 0
```

2. Add the `TargetPickPhase`/`TargetPickEntryModel`/`TargetPickUiState` types near `MethodScanUiState`.

3. Actions:

```kotlin
    fun requestTargetPick() {
        viewModelScope.launch {
            lastPickGeneration += 1
            service?.requestTargetPick(_runtimeFilesState.value.activeProfileId)
        }
    }

    fun cancelTargetPick() {
        service?.cancelTargetPick()
    }

    fun chooseTarget(entry: TargetPickEntryModel) {
        viewModelScope.launch {
            val profileId = _runtimeFilesState.value.activeProfileId
            val configEditor = _runtimeFilesState.value.configEditor
            val kind = TargetPickPolicy.pinKindForMode(configEditor.valueFor("MODE")) ?: return@launch
            val pin = TargetPin(
                kind = kind,
                sni = entry.sni,
                ip = entry.ip,
                score = entry.score.takeIf { it > 0 },
                pickedAtMs = System.currentTimeMillis(),
            )
            runCatching { pinStore.write(profileId, pin) }
                .onSuccess {
                    _targetPickState.update { it.copy(pin = pin) }
                    service?.applyTargetPick()                }
                .onFailure { error ->
                    _targetPickState.update {
                        it.copy(phase = TargetPickPhase.Failed(error.message ?: "Could not save the target pin."))
                    }
                }
        }
    }

    fun clearTargetPin() {
        viewModelScope.launch {
            val profileId = _runtimeFilesState.value.activeProfileId
            runCatching { pinStore.clear(profileId) }
                .onSuccess {
                    _targetPickState.update { it.copy(pin = null) }
                    _runtimeFilesState.update {
                        it.copy(statusMessage = "Cleared the pinned target; the next start will scan and ask again.")
                    }
                }
                .onFailure { error ->
                    _runtimeFilesState.update {
                        it.copy(errorMessage = error.message ?: "Could not clear the target pin.")
                    }
                }
        }
    }

    fun refreshTargetPin() {
        viewModelScope.launch {
            val profileId = _runtimeFilesState.value.activeProfileId
            val pin = runCatching { pinStore.read(profileId) }.getOrNull()
            _targetPickState.update { it.copy(pin = pin) }
        }
    }
```

4. State driver `updateTargetPickState(serviceState)` mirroring `updateMethodScanState`; call it from the same three sites (`onServiceConnected` collector, `onServiceDisconnected`, and inside `syncIdleRuntimeStateFromConfig` after `updateMethodScanState`). Visible rule and transitions:

```kotlin
    private fun updateTargetPickState(serviceState: ZeroDpiServiceState) {
        val editor = _runtimeFilesState.value.configEditor
        val mode = editor.valueFor("MODE")
        val visible = TargetPickPolicy.scanModeFor(mode) != null &&
            editor.valueFor("AUTO_SELECT") == "false"
        if (!visible) {
            _targetPickState.value = TargetPickUiState()
            return
        }
        val session = serviceState.pickSession
        val previousPhase = _targetPickState.value.phase
        val currentPin = _targetPickState.value.pin
        when {
            session?.phase == PickPhase.Choosing -> {
                if (loadedPickGeneration != lastPickGeneration) {
                    loadedPickGeneration = lastPickGeneration
                    loadPickResults(mode)
                } else {
                    _targetPickState.value = TargetPickUiState(
                        phase = TargetPickPhase.Choosing,
                        mode = mode,
                        pin = currentPin,
                        entries = _targetPickState.value.entries,
                        resumeAvailable = session.resumeAvailable,
                        origin = session.origin,
                    )
                }
            }
            session?.phase == PickPhase.Scanning -> {
                _targetPickState.value = TargetPickUiState(
                    phase = TargetPickPhase.Scanning,
                    mode = mode,
                    pin = currentPin,
                    progress = serviceState.scanProgress,
                    resumeAvailable = session.resumeAvailable,
                    origin = session.origin,
                )
            }
            else -> {
                if (previousPhase != TargetPickPhase.Idle) {
                    refreshTargetPin() // also updates the pin mirror
                }
                _targetPickState.value = TargetPickUiState(
                    phase = TargetPickPhase.Idle,
                    mode = mode,
                    pin = _targetPickState.value.pin,
                    resumeAvailable = session?.resumeAvailable ?: false,
                    origin = session?.origin,
                )
            }
        }
    }
```

Fields: `private var lastPickGeneration = 0` (incremented at the start of `requestTargetPick()`), `private var loadedPickGeneration = -1`, `private var pinSnapshot: TargetPin? = null`. `refreshTargetPin()` reads the store and updates both `pinSnapshot` and the state's `pin`; `chooseTarget`/`clearTargetPin` update `pinSnapshot` too. (The exact shape is up to you as long as: Idle shows the current pin; Choosing loads entries exactly once per scan generation; Failed shows the message and clears on the next request.)

`loadPickResults(mode)`:

```kotlin
    private fun loadPickResults(mode: String) {
        viewModelScope.launch {
            val profileId = _runtimeFilesState.value.activeProfileId
            val raw = runCatching { runtimeStorage.readPickScanResults(profileId) }.getOrNull()
            val entries = raw?.let { text ->
                when (TargetPickPolicy.scanModeFor(mode)) {
                    "sni_scan" -> ScanResultParser.parseSni(text)
                    "ip_scan" -> ScanResultParser.parseIp(text)
                    else -> null
                }?.map { entry ->
                    when (entry) {
                        is SniScanEntryModel -> TargetPickEntryModel(entry.sni, entry.ip, entry.score, entry.tcpLatencyMs)
                        is IpScanEntryModel -> TargetPickEntryModel(null, entry.ip, entry.score, entry.tcpLatencyMs)
                    }
                }
            }
            _targetPickState.value = if (entries != null) {
                TargetPickUiState(
                    phase = TargetPickPhase.Choosing,
                    mode = mode,
                    pin = _targetPickState.value.pin,
                    entries = entries,
                    resumeAvailable = _targetPickState.value.resumeAvailable,
                    origin = _targetPickState.value.origin,
                )
            } else {
                TargetPickUiState(
                    phase = TargetPickPhase.Failed(
                        raw?.let { "Scan results could not be parsed." }
                            ?: "The scan finished without results. Check the SNI/IP list and try again.",
                    ),
                    mode = mode,
                    pin = _targetPickState.value.pin,
                )
            }
        }
    }
```

(Keep the `lastPickGeneration`/`loadedPickGeneration` pair so a Choosing→Idle→Choosing cycle re-reads the file exactly once per scan.)

5. Clear-pin policy on config save: inside `saveRuntimeFiles`, after a successful save of `RuntimeFileKind.Config`, if the saved text's editor (`ZeroDpiConfigToml.analyze(snapshot.textFor(RuntimeFileKind.Config))`) has a non-blank `SELECTED_SNI` or `SELECTED_IP`, call `pinStore.clear(profileId)` best-effort and update the mirror:

```kotlin
                onSuccess = {
                    if (RuntimeFileKind.Config in filesToSave) {
                        val savedEditor = ZeroDpiConfigToml.analyze(snapshot.textFor(RuntimeFileKind.Config))
                        if (savedEditor.valueFor("SELECTED_SNI").isNotBlank() ||
                            savedEditor.valueFor("SELECTED_IP").isNotBlank()
                        ) {
                            runCatching { pinStore.clear(snapshot.activeProfileId) }
                            _targetPickState.update { it.copy(pin = null) }
                        }
                    }
                    // ... existing body unchanged
                },
```

6. Profile switch / load: after `loadRuntimeFiles()` completes and after profile switches, call `refreshTargetPin()` (find the existing post-load hooks and add the call).

- [ ] **Step 4: Run the instrumented tests**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.ui.MainViewModelInstrumentedTest`
Expected: the two new tests PASS and the existing ones stay green. (If the fake runner's `request.configPath` does not point into the runtime dir in the VM test environment, assert on what the actual file layout produces — `pick_scan_results.json` must land in the same directory the ephemeral config is written to, which `prepareRunConfig` guarantees.)

- [ ] **Step 5: Run unit tests**

Run: `cd android && ./gradlew.bat testDebugUnitTest`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/ui/MainViewModel.kt android/app/src/androidTest/java/dev/zerodpi/android/ui/MainViewModelInstrumentedTest.kt
git commit -m "feat(android): add target picker view-model state, actions, and pin-clear policy"
```

---

### Task 7: TargetPickerCard UI and Home wiring

**Files:**
- Create: `android/app/src/main/java/dev/zerodpi/android/ui/TargetPickerCard.kt`
- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/HomeScreen.kt` (parameter + card slot)
- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/DashboardScreen.kt` (pass-through)
- Modify: `android/app/src/main/java/dev/zerodpi/android/MainActivity.kt` (pass-through)
- Modify: `android/app/src/main/res/values/strings.xml`
- Test: `android/app/src/androidTest/java/dev/zerodpi/android/ui/TargetPickerCardTest.kt` (create)

**Interfaces:**
- Consumes: `TargetPickUiState`, `TargetPickPhase`, `TargetPickEntryModel`, `ScanProgressInfo`, `TargetPin`, `PickOrigin` (Tasks 4–6).
- Produces: `TargetPickerCard(state, onRequestPick, onCancelPick, onChoose, onClearPin, modifier)`; testTags `target_pick_card`, `target_pick_scan`, `target_pick_clear`, `target_pick_cancel`, `target_pick_progress`, `target_pick_row_<index>`, `target_pick_row_<sni|ip>`.

- [ ] **Step 1: Write the failing compose tests**

Create `android/app/src/androidTest/java/dev/zerodpi/android/ui/TargetPickerCardTest.kt` (mirror `MethodScanCardTest`):

```kotlin
package dev.zerodpi.android.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import dev.zerodpi.android.service.PickOrigin
import dev.zerodpi.android.service.ScanProgressInfo
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.TargetPin
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class TargetPickerCardTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val sniPin = TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L)

    @Test
    fun hiddenPhaseRendersNothing() {
        composeRule.setContent {
            TargetPickerCard(state = TargetPickUiState())
        }
        composeRule.onNodeWithTag("target_pick_card").assertDoesNotExist()
    }

    @Test
    fun idleWithoutPinOffersScanAndChoose() {
        var requested = false
        composeRule.setContent {
            TargetPickerCard(
                state = TargetPickUiState(phase = TargetPickPhase.Idle, mode = "sni_spoof"),
                onRequestPick = { requested = true },
            )
        }
        composeRule.onNodeWithTag("target_pick_scan").performClick()
        assertTrue(requested)
    }

    @Test
    fun idleWithPinShowsTargetAndClearAction() {
        composeRule.setContent {
            TargetPickerCard(state = TargetPickUiState(phase = TargetPickPhase.Idle, mode = "sni_spoof", pin = sniPin))
        }
        composeRule.onNodeWithText("cloudflare.com (1.1.1.1)").assertIsDisplayed()
        composeRule.onNodeWithTag("target_pick_clear").assertIsDisplayed()
    }

    @Test
    fun choosingRendersRankedRowsAndDisablesFailedRows() {
        var chosen: TargetPickEntryModel? = null
        composeRule.setContent {
            TargetPickerCard(
                state = TargetPickUiState(
                    phase = TargetPickPhase.Choosing,
                    mode = "sni_spoof",
                    origin = PickOrigin.Standalone,
                    entries = listOf(
                        TargetPickEntryModel("cloudflare.com", "1.1.1.1", 95, 35L),
                        TargetPickEntryModel("unreachable.example", "10.0.0.1", 0, null),
                    ),
                ),
                onChoose = { chosen = it },
            )
        }
        composeRule.onNodeWithTag("target_pick_row_0").assertIsDisplayed()
        composeRule.onNodeWithTag("target_pick_row_0").performClick()
        assertTrue(chosen?.sni == "cloudflare.com")
    }

    @Test
    fun scanningShowsProgressAndCancel() {
        composeRule.setContent {
            TargetPickerCard(
                state = TargetPickUiState(
                    phase = TargetPickPhase.Scanning,
                    mode = "sni_spoof",
                    progress = ScanProgressInfo(scan = "sni", completed = 2, total = 5),
                ),
            )
        }
        composeRule.onNodeWithTag("target_pick_progress").assertIsDisplayed()
        composeRule.onNodeWithTag("target_pick_cancel").assertIsDisplayed()
    }

    @Test
    fun failedShowsMessage() {
        composeRule.setContent {
            TargetPickerCard(state = TargetPickUiState(phase = TargetPickPhase.Failed("boom"), mode = "sni_spoof"))
        }
        composeRule.onNodeWithTag("target_pick_error").assertIsDisplayed()
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.ui.TargetPickerCardTest`
Expected: compilation fails — card/state unresolved.

- [ ] **Step 3: Implement the card**

Create `android/app/src/main/java/dev/zerodpi/android/ui/TargetPickerCard.kt`:

```kotlin
package dev.zerodpi.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.zerodpi.android.R
import dev.zerodpi.android.service.ScanProgressInfo

@Composable
internal fun TargetPickerCard(
    state: TargetPickUiState,
    modifier: Modifier = Modifier,
    onRequestPick: () -> Unit = {},
    onCancelPick: () -> Unit = {},
    onChoose: (TargetPickEntryModel) -> Unit = {},
    onClearPin: () -> Unit = {},
) {
    when (state.phase) {
        TargetPickPhase.Hidden -> Unit

        TargetPickPhase.Idle -> IdleCard(state, modifier, onRequestPick, onClearPin)

        TargetPickPhase.Scanning -> ScanningCard(state, modifier, onCancelPick)

        TargetPickPhase.Choosing -> ChoosingCard(state, modifier, onCancelPick, onChoose)

        is TargetPickPhase.Failed -> SectionCard(
            title = stringResource(R.string.target_pick_title),
            modifier = modifier.testTag("target_pick_card"),
        ) {
            Text(
                text = state.phase.message,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag("target_pick_error"),
            )
            OutlinedButton(onClick = onRequestPick, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_scan_choose))
            }
        }
    }
}

@Composable
private fun IdleCard(
    state: TargetPickUiState,
    modifier: Modifier,
    onRequestPick: () -> Unit,
    onClearPin: () -> Unit,
) {
    SectionCard(
        title = stringResource(R.string.target_pick_title),
        modifier = modifier.testTag("target_pick_card"),
    ) {
        val pin = state.pin
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (pin == null) {
                Text(stringResource(R.string.target_pick_idle_no_pin))
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(
                            R.string.target_pick_pinned,
                            pin.sni ?: pin.ip,
                            pin.sni?.let { pin.ip } ?: "",
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                    )
                    IconButton(onClick = onClearPin, modifier = Modifier.testTag("target_pick_clear")) {
                        Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.action_clear_pin))
                    }
                }
            }
            OutlinedButton(
                onClick = onRequestPick,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_scan"),
            ) {
                Icon(Icons.Default.Search, contentDescription = null)
                Text(
                    stringResource(R.string.action_scan_choose),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun ScanningCard(
    state: TargetPickUiState,
    modifier: Modifier,
    onCancelPick: () -> Unit,
) {
    val completed = state.progress?.completed ?: 0
    val total = state.progress?.total ?: 1
    SectionCard(
        title = stringResource(R.string.target_pick_title),
        modifier = modifier.testTag("target_pick_card"),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.target_pick_scanning))
            LinearProgressIndicator(
                progress = { (completed.toFloat() / total.coerceAtLeast(1)).coerceIn(0f, 1f) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_progress"),
            )
            Text(
                text = stringResource(R.string.target_pick_progress, completed, total),
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(
                onClick = onCancelPick,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_cancel"),
            ) {
                Icon(Icons.Default.Close, contentDescription = null)
                Text(stringResource(R.string.action_cancel), modifier = Modifier.padding(start = 8.dp))
            }
        }
    }
}

@Composable
private fun ChoosingCard(
    state: TargetPickUiState,
    modifier: Modifier,
    onCancelPick: () -> Unit,
    onChoose: (TargetPickEntryModel) -> Unit,
) {
    SectionCard(
        title = stringResource(R.string.target_pick_title),
        modifier = modifier.testTag("target_pick_card"),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.target_pick_choose_prompt))
            Row(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.target_pick_column_rank), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(4f)) {
                    Text(stringResource(R.string.target_pick_column_target), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.target_pick_column_score), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
                Column(modifier = Modifier.weight(2f)) {
                    Text(stringResource(R.string.target_pick_column_latency), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelSmall)
                }
            }
            state.entries.orEmpty().forEachIndexed { index, entry ->
                PickRow(index, entry, enabled = entry.score > 0, onChoose = onChoose)
            }
            if (state.entries.orEmpty().isEmpty()) {
                Text(stringResource(R.string.target_pick_no_results), color = MaterialTheme.colorScheme.error)
            }
            OutlinedButton(
                onClick = onCancelPick,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("target_pick_cancel"),
            ) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    }
}

@Composable
private fun PickRow(
    index: Int,
    entry: TargetPickEntryModel,
    enabled: Boolean,
    onChoose: (TargetPickEntryModel) -> Unit,
) {
    val rowModifier = Modifier
        .fillMaxWidth()
        .testTag("target_pick_row_$index")
        .then(if (enabled) Modifier.clickable { onChoose(entry) } else Modifier)
    Row(modifier = rowModifier, verticalAlignment = Alignment.CenterVertically) {
        Column(modifier = Modifier.weight(1f)) { Text((index + 1).toString(), style = MaterialTheme.typography.bodySmall) }
        Column(modifier = Modifier.weight(4f)) {
            Text(entry.sni ?: entry.ip, style = MaterialTheme.typography.bodySmall)
            if (entry.sni != null) {
                Text(entry.ip, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.score.toString(), style = MaterialTheme.typography.bodySmall)
            if (!enabled) {
                Text(stringResource(R.string.target_pick_row_failed), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(entry.tcpLatencyMs?.let { "$it ms" } ?: stringResource(R.string.value_not_available), style = MaterialTheme.typography.bodySmall)
        }
    }
}
```

Add the strings to `strings.xml` (values are illustrative — keep the tone of existing strings; the literal label used by the compose test for the pinned row must match `target_pick_pinned`'s formatting):

```xml
    <string name="target_pick_title">Target picker</string>
    <string name="target_pick_idle_no_pin">No pinned target. AUTO_SELECT is off, so starting ZeroDPI will scan and ask you to choose.</string>
    <string name="target_pick_pinned">Pinned target %1$s%2$s</string>
    <string name="target_pick_scanning">Scanning for reachable targets…</string>
    <string name="target_pick_progress">%1$d/%2$d candidates probed</string>
    <string name="target_pick_choose_prompt">Choose the target to run with (score 0 rows failed and are disabled):</string>
    <string name="target_pick_no_results">The scan produced no candidates.</string>
    <string name="target_pick_row_failed">failed</string>
    <string name="target_pick_column_rank">#</string>
    <string name="target_pick_column_target">Target</string>
    <string name="target_pick_column_score">Score</string>
    <string name="target_pick_column_latency">TCP</string>
    <string name="action_scan_choose">Scan &amp; choose</string>
    <string name="action_clear_pin">Clear pin</string>
    <string name="action_cancel">Cancel</string>
```

If `target_pick_pinned` uses a single placeholder for simplicity, adjust the IdleCard row text and the compose test accordingly — the two must agree.

- [ ] **Step 4: Wire the card into the screen hierarchy**

1. `HomeScreen.kt`: add parameter `targetPickState: TargetPickUiState` plus callbacks `onRequestTargetPick: () -> Unit`, `onCancelTargetPick: () -> Unit`, `onChooseTarget: (TargetPickEntryModel) -> Unit`, `onClearTargetPin: () -> Unit`; render `TargetPickerCard(state = targetPickState, onRequestPick = onRequestTargetPick, onCancelPick = onCancelTargetPick, onChoose = onChooseTarget, onClearPin = onClearTargetPin)` between `RuntimeStatusCard` and `MethodScanCard`; add a `Modifier.testTag("target_pick_slot")` if desired (not required).
2. `DashboardScreen.kt`: in the `AppDestination.Home -> HomeScreen(...)` call, thread the new state and callbacks through (add parameters to `DashboardScreen` signature and forward from `MainActivity`).
3. `MainActivity.kt`: add `targetPickState = viewModel.targetPickState.collectAsState().value`-style values at the call site, and `onRequestTargetPick = viewModel::requestTargetPick`, `onCancelTargetPick = viewModel::cancelTargetPick`, `onChooseTarget = viewModel::chooseTarget`, `onClearTargetPin = viewModel::clearTargetPin` — mirror exactly how the existing `methodScanState`/`MethodScanCard` state and callbacks are threaded (read `MainActivity.kt` and `DashboardScreen.kt` and copy that pattern).

- [ ] **Step 5: Run the compose tests**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.ui.TargetPickerCardTest`
Expected: PASS. (Adjust the pinned-row string formatting in the test to match the actual resource.)

- [ ] **Step 6: Run the UI suites for regressions**

Run: `cd android && ./gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.zerodpi.android.ui.DashboardScreenTest` and `...MainViewModelInstrumentedTest`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/ui/TargetPickerCard.kt android/app/src/main/java/dev/zerodpi/android/ui/HomeScreen.kt android/app/src/main/java/dev/zerodpi/android/ui/DashboardScreen.kt android/app/src/main/java/dev/zerodpi/android/MainActivity.kt android/app/src/main/res/values/strings.xml android/app/src/androidTest/java/dev/zerodpi/android/ui/TargetPickerCardTest.kt
git commit -m "feat(android): add target picker card to the home tab"
```

---

### Task 8: Docs, full verification, and manual QA checklist

**Files:**
- Modify: `android/README.md` (Android parity table/paragraph)
- Modify: `README.md` only if it has an Android-app feature list that must mention target picking (match the existing Android parity wording added in commit `42ac718`)

- [ ] **Step 1: Update the Android README parity section**

In `android/README.md`, extend the runtime-modes/features prose (the section describing what the app does, near the top) with one paragraph:

```markdown
### Target scan &amp; pick (AUTO_SELECT = false)

When the config has `AUTO_SELECT = false` and no `SELECTED_SNI`/`SELECTED_IP`
and no app-side pin, tapping **Start** first runs a rootless scan against the
active profile's SNI/IP list and shows the ranked results on the Home tab.
Choosing a row pins that target app-side (`target_pin.json` in the profile
runtime directory) and starts the run with it. The pin is injected at launch
through an ephemeral run config — `config.toml` is never rewritten. The Home
tab also offers **Scan &amp; choose** while stopped (saves the pin only) and
while running (gracefully restarts the data plane with the new pick) plus
**Clear pin** to return to scan-and-ask behavior. Pins are per profile and are
never included in support bundles or profile exports.
```

- [ ] **Step 2: Run the full Android verification**

Run from repo root:

```bash
cd android && ./gradlew.bat testDebugUnitTest
cd android && ./gradlew.bat connectedDebugAndroidTest
```

Expected: full unit + instrumented suites PASS (device/emulator required for the second command).

- [ ] **Step 3: Run Rust-side sanity (should be untouched)**

```bash
cargo test --workspace
cargo fmt --all -- --check
```

Expected: PASS — nothing under `crates/` changed in this plan.

- [ ] **Step 4: Manual QA checklist (record results in the PR description)**

On a device with a debug build (fake runner) and, if available, a release full/rootless build:
1. Config `AUTO_SELECT = false`, no pin: Start → scan progress on Home card → ranked list → pick → run starts with the target shown on the dashboard summary; `config.toml` on disk does not contain `SELECTED_SNI`.
2. Same flow, pick from a `sni_spoof` config, then switch the config `MODE` to `ip_bypass` and Start: IP scan/choose flow appears (SNI pin ignored).
3. While running with a pin: **Scan & choose** → runtime stops briefly → scan → pick a different row → runtime relaunches with the new target; pick → cancel → previous run resumes unchanged.
4. While stopped with a pin: **Scan & choose** → pick → nothing starts; **Start** then runs the pinned target without scanning.
5. **Clear pin** → Start scans and asks again.
6. Set `SELECTED_SNI` in the config editor and save → the app pin disappears (cleared); run uses the manual value.
7. `AUTO_SELECT = true`: no target-picker card is shown; behavior unchanged from before this feature.
8. Support bundle export does not include `target_pin.json`; profile export/import does not carry pins.

- [ ] **Step 5: Commit**

```bash
git add android/README.md README.md
git commit -m "docs(android): document target scan and pick flow"
```

---

## Self-Review Notes (executor)

- Spec coverage: behavior table rows map to Task 5 (service) + Task 6 (ViewModel) + Task 7 (UI); persistence rules map to Tasks 1–3 (pin store + injection) and Task 6 step 5 (clear-on-manual-save); edge policies (kind mismatch, clear-pin semantics, support-bundle exclusion) covered in Tasks 2–3, 6, and 8. No Rust changes anywhere.
- Verify at Task 5 that `launchRun` has a single call site for runner start and that the Start gate return path cannot double-start; run the full `ZeroDpiServiceInstrumentedTest` (Step 6) to catch regressions in the existing network-restart flow.
- If `ProfileRepository.DEFAULT_PROFILE_ID` does not exist, use `ZeroDpiProfile.DEFAULT_PROFILE_ID` (referenced in `ZeroDpiServiceInstrumentedTest`).
