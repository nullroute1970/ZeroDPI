package dev.zerodpi.android.runtime

import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * JVM tests for the fake runner's exit-once semantics. The fake mirrors the
 * real [ProcessZeroDpiRunner] contract that [ZeroDpiService] relies on: the
 * exit event is emitted at most once per run, and stop()/forceStop() report
 * whether this call performed the emission or the exit was already gone.
 */
class FakeZeroDpiRunnerTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun stopWithoutActiveRunEmitsExitExactlyOnce() = runBlocking {
        val runner = FakeZeroDpiRunner(this)
        val events = collectEvents(runner) {
            // No run was started: like the real runner, the first stop still
            // emits a clean exit so callers never wait on a missing event.
            assertEquals(RunnerStopResult.Exited, runner.stop())
            // The second stop has nothing left to report.
            assertEquals(RunnerStopResult.AlreadyExited, runner.stop())
        }

        assertEquals(listOf(ZeroDpiRunnerEvent.Exited(0)), events)
    }

    @Test
    fun forceStopOnRunningRelayRunEmitsSingleExit() = runBlocking {
        val runner = FakeZeroDpiRunner(this)
        val events = collectEvents(runner) { collected ->
            runner.start(relayRequest())
            withTimeout(5_000) {
                while (collected.none { it is ZeroDpiRunnerEvent.ListenerStarted }) {
                    delay(10)
                }
            }
            assertEquals(RunnerStopResult.Exited, runner.forceStop())
            assertEquals(RunnerStopResult.AlreadyExited, runner.forceStop())
        }

        assertEquals(1, events.count { it is ZeroDpiRunnerEvent.Exited })
    }

    @Test
    fun naturalScanModeExitMakesLaterStopReportAlreadyExited() = runBlocking {
        val runner = FakeZeroDpiRunner(this)
        val config = File(temporaryFolder.root, "config.toml").apply {
            writeText("MODE = \"sni_scan\"\n")
        }
        val request = ZeroDpiRunRequest(
            configPath = config.absolutePath,
            workingDirectory = temporaryFolder.root.absolutePath,
            mode = "sni_scan",
            listenHost = "127.0.0.1",
            listenPort = 44444,
        )
        val events = collectEvents(runner) { collected ->
            runner.start(request)
            withTimeout(5_000) {
                while (collected.none { it is ZeroDpiRunnerEvent.Exited }) {
                    delay(10)
                }
            }
            // The scan-mode run ended by itself: the exit event is already
            // gone, exactly like a real process that exited before a stop.
            assertEquals(RunnerStopResult.AlreadyExited, runner.stop())
        }

        assertEquals(1, events.count { it is ZeroDpiRunnerEvent.Exited })
        assertTrue(events.any { it is ZeroDpiRunnerEvent.ScanCompleted })
    }

    private fun relayRequest(): ZeroDpiRunRequest {
        val config = File(temporaryFolder.root, "relay-config.toml").apply {
            writeText("AUTO_SELECT = true\nSELECTED_SNI = \"pinned.example.net\"\n")
        }
        return ZeroDpiRunRequest(
            configPath = config.absolutePath,
            workingDirectory = temporaryFolder.root.absolutePath,
            mode = "sni_spoof",
            listenHost = "127.0.0.1",
            listenPort = 44444,
        )
    }

    private suspend fun collectEvents(
        runner: FakeZeroDpiRunner,
        block: suspend (List<ZeroDpiRunnerEvent>) -> Unit,
    ): List<ZeroDpiRunnerEvent> = coroutineScope {
        val events = mutableListOf<ZeroDpiRunnerEvent>()
        val collector = launch {
            runner.events().collect { event ->
                events += event
            }
        }
        yield()
        block(events)
        delay(50)
        collector.cancel()
        events.toList()
    }
}
