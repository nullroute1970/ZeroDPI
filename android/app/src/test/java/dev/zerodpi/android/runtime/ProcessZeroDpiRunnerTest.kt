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
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit

class ProcessZeroDpiRunnerTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun rootlessStartUsesPackagedExecutableCommandAndParsesEvents() = runBlocking {
        val executable = temporaryFolder.newFile("libzerodpi_exec.so")
        val workingDirectory = temporaryFolder.newFolder("runtime")
        val configFile = temporaryFolder.newFile("config.toml")
        val processLauncher = RecordingProcessLauncher(
            FakeProcess(
                stdout = """
                    {"event":"config_loaded","mode":"sni_spoof","bypass_method":"tls_frag","listen_host":"127.0.0.1","listen_port":44444,"root_required":false}
                """.trimIndent(),
            ),
        )
        val runner = ProcessZeroDpiRunner(
            scope = this,
            rootManager = FakeRootManager(),
            executableProvider = { executable },
            processLauncher = processLauncher,
        )

        val events = collectRunnerEventsUntil(
            runner = runner,
            complete = { collected ->
                collected.any { it is ZeroDpiRunnerEvent.ConfigLoaded } &&
                    collected.any { it is ZeroDpiRunnerEvent.Exited }
            },
        ) {
            runner.start(
                ZeroDpiRunRequest(
                    configPath = configFile.absolutePath,
                    workingDirectory = workingDirectory.absolutePath,
                    useRoot = false,
                ),
            )
        }

        assertEquals(
            listOf(
                executable.absolutePath,
                "--config",
                configFile.absolutePath,
                "--no-tui",
                "--auto-select",
                "--json-events",
            ),
            processLauncher.commands.single(),
        )
        assertEquals(workingDirectory, processLauncher.workingDirectories.single())
        assertTrue(events.any { it == ZeroDpiRunnerEvent.Starting })
        assertTrue(
            events.any {
                it is ZeroDpiRunnerEvent.ConfigLoaded &&
                    it.mode == "sni_spoof" &&
                    it.bypassMethod == "tls_frag" &&
                    it.listenPort == 44444 &&
                    !it.rootRequired
            },
        )
        assertTrue(events.any { it is ZeroDpiRunnerEvent.Exited && it.exitCode == 0 })
    }

    @Test
    fun stopAfterNaturalProcessExitReportsAlreadyExited() = runBlocking {
        val executable = temporaryFolder.newFile("libzerodpi_exec.so")
        val workingDirectory = temporaryFolder.newFolder("runtime")
        val configFile = temporaryFolder.newFile("config.toml")
        val runner = ProcessZeroDpiRunner(
            scope = this,
            rootManager = FakeRootManager(),
            executableProvider = { executable },
            processLauncher = RecordingProcessLauncher(FakeProcess()),
        )

        collectRunnerEventsUntil(
            runner = runner,
            complete = { collected -> collected.any { it is ZeroDpiRunnerEvent.Exited } },
        ) {
            runner.start(
                ZeroDpiRunRequest(
                    configPath = configFile.absolutePath,
                    workingDirectory = workingDirectory.absolutePath,
                    useRoot = false,
                ),
            )
        }

        // The exit event was already emitted by the process wait job, so a
        // later stop must report AlreadyExited instead of waiting for an exit
        // event that will never arrive (the supervised-restart deadlock).
        assertEquals(RunnerStopResult.AlreadyExited, runner.stop())
        assertEquals(RunnerStopResult.AlreadyExited, runner.forceStop())
    }

    @Test
    fun abandonKillsSilentRunWithoutReportingAnExit() = runBlocking {
        val executable = temporaryFolder.newFile("libzerodpi_exec.so")
        val workingDirectory = temporaryFolder.newFolder("runtime")
        val configFile = temporaryFolder.newFile("config.toml")
        val process = HangingFakeProcess()
        val processLauncher = RecordingProcessLauncher(process)
        val runner = ProcessZeroDpiRunner(
            scope = this,
            rootManager = FakeRootManager(),
            executableProvider = { executable },
            processLauncher = processLauncher,
        )
        val events = mutableListOf<ZeroDpiRunnerEvent>()
        val collector = launch { runner.events().collect { events += it } }

        try {
            yield()
            runner.start(
                ZeroDpiRunRequest(
                    configPath = configFile.absolutePath,
                    workingDirectory = workingDirectory.absolutePath,
                    useRoot = false,
                ),
            )
            assertTrue(process.isAlive)

            runner.abandon()
            delay(200)

            // The wedged child is gone, no exit event was fabricated for the
            // abandoned run, and a later start is not blocked by it.
            assertTrue(!process.isAlive)
            assertTrue(events.none { it is ZeroDpiRunnerEvent.Exited })
            assertEquals(RunnerStopResult.AlreadyExited, runner.stop())
            assertEquals(RunnerStopResult.AlreadyExited, runner.forceStop())

            runner.start(
                ZeroDpiRunRequest(
                    configPath = configFile.absolutePath,
                    workingDirectory = workingDirectory.absolutePath,
                    useRoot = false,
                ),
            )
            assertEquals(2, processLauncher.commands.size)
        } finally {
            collector.cancel()
        }
    }

    @Test
    fun rootStartLaunchesOnlyHelperAsRootAndDataPlaneNormally() = runBlocking {
        val executable = temporaryFolder.newFile("libzerodpi_exec.so")
        val helperExecutable = temporaryFolder.newFile("libzerodpi_root_helper_exec.so")
        val workingDirectory = temporaryFolder.newFolder("runtime")
        val helperBootstrapParent = temporaryFolder.newFolder("helper-bootstrap")
        val configFile = temporaryFolder.newFile("config.toml")
        val rootManager = FakeRootManager(
            launchProcess = FakeProcess(
                stdout = "ZERODPI_HELPER_READY pid=1234 uid=0\n",
            ),
        )
        val processLauncher = RecordingProcessLauncher(
            FakeProcess(
                stdout = """
                    {"event":"startup","version":"0.1.0","pid":5678,"uid":10123}
                    {"event":"helper_authenticated","pid":1234,"uid":0,"protocol_major":1,"protocol_minor":0,"capabilities":["nfqueue"]}
                    {"event":"listener_started","mode":"sni_spoof","listen_addr":"127.0.0.1:44444"}
                """.trimIndent(),
            ),
        )
        val runner = ProcessZeroDpiRunner(
            scope = this,
            rootManager = rootManager,
            executableProvider = { executable },
            processLauncher = processLauncher,
            helperExecutableProvider = { helperExecutable },
            appUidProvider = { 10123 },
            appPidProvider = { 777 },
            sessionProofProvider = { ByteArray(32) { 7 } },
            fileModeSetter = { _, _ -> },
            helperBootstrapParentProvider = { helperBootstrapParent },
        )

        val events = collectRunnerEventsUntil(
            runner = runner,
            complete = { collected ->
                collected.any { it is ZeroDpiRunnerEvent.Failed } ||
                    (collected.any { it is ZeroDpiRunnerEvent.ListenerStarted } &&
                        collected.any { it is ZeroDpiRunnerEvent.Exited })
            },
        ) {
            runner.start(
                ZeroDpiRunRequest(
                    configPath = configFile.absolutePath,
                    workingDirectory = workingDirectory.absolutePath,
                    useRoot = true,
                ),
            )
        }

        assertTrue(events.toString(), events.none { it is ZeroDpiRunnerEvent.Failed })
        assertEquals(helperExecutable, rootManager.launches.single().executable)
        assertEquals(workingDirectory, rootManager.launches.single().workingDirectory)
        assertEquals(10123, rootManager.launches.single().expectedAppUid)
        assertEquals(helperBootstrapParent, rootManager.launches.single().socketPath.parentFile?.parentFile)
        assertEquals(executable.absolutePath, processLauncher.commands.single().first())
        assertTrue(processLauncher.commands.single().contains("--root-helper-socket"))
        assertTrue(processLauncher.commands.single().contains("--expected-data-plane-uid"))
        assertTrue(events.any { it is ZeroDpiRunnerEvent.RootHelperAuthenticated && it.uid == 0L })
        assertTrue(events.any { it is ZeroDpiRunnerEvent.DataPlaneStarted && it.uid == 10123L })
        assertTrue(events.any { it is ZeroDpiRunnerEvent.ListenerStarted && it.listenAddress == "127.0.0.1:44444" })
    }

    @Test
    fun helperFailureBeforeReadinessPreventsDataPlaneLaunch() = runBlocking {
        val executable = temporaryFolder.newFile("libzerodpi_exec.so")
        val helperExecutable = temporaryFolder.newFile("libzerodpi_root_helper_exec.so")
        val workingDirectory = temporaryFolder.newFolder("failed-helper-runtime")
        val configFile = temporaryFolder.newFile("failed-helper-config.toml")
        val rootManager = FakeRootManager(launchProcess = FakeProcess(stdout = "helper failed\n", exitCode = 1))
        val processLauncher = RecordingProcessLauncher(FakeProcess())
        val runner = ProcessZeroDpiRunner(
            scope = this,
            rootManager = rootManager,
            executableProvider = { executable },
            processLauncher = processLauncher,
            helperExecutableProvider = { helperExecutable },
            appUidProvider = { 10123 },
            appPidProvider = { 777 },
            sessionProofProvider = { ByteArray(32) { 9 } },
            fileModeSetter = { _, _ -> },
        )

        val events = collectRunnerEventsUntil(runner, { items -> items.any { it is ZeroDpiRunnerEvent.Failed } }) {
            runner.start(
                ZeroDpiRunRequest(
                    configPath = configFile.absolutePath,
                    workingDirectory = workingDirectory.absolutePath,
                    useRoot = true,
                ),
            )
        }

        assertTrue(
            events.any {
                it is ZeroDpiRunnerEvent.Failed &&
                    it.message.contains("exited before listener readiness with code 1") &&
                    it.message.contains("Last output: helper failed")
            },
        )
        assertTrue(processLauncher.commands.isEmpty())
    }

    @Test
    fun dataPlaneUidMismatchFailsClosed() = runBlocking {
        val executable = temporaryFolder.newFile("libzerodpi_exec.so")
        val helperExecutable = temporaryFolder.newFile("libzerodpi_root_helper_exec.so")
        val workingDirectory = temporaryFolder.newFolder("uid-runtime")
        val configFile = temporaryFolder.newFile("uid-config.toml")
        val rootManager = FakeRootManager(
            launchProcess = FakeProcess(stdout = "ZERODPI_HELPER_READY pid=1234 uid=0\n"),
        )
        val processLauncher = RecordingProcessLauncher(
            FakeProcess(stdout = """{"event":"startup","version":"0.1.0","pid":5678,"uid":0}"""),
        )
        val runner = ProcessZeroDpiRunner(
            scope = this,
            rootManager = rootManager,
            executableProvider = { executable },
            processLauncher = processLauncher,
            helperExecutableProvider = { helperExecutable },
            appUidProvider = { 10123 },
            appPidProvider = { 777 },
            sessionProofProvider = { ByteArray(32) { 5 } },
            fileModeSetter = { _, _ -> },
        )

        val events = collectRunnerEventsUntil(runner, { items -> items.any { it is ZeroDpiRunnerEvent.Failed } }) {
            runner.start(
                ZeroDpiRunRequest(
                    configPath = configFile.absolutePath,
                    workingDirectory = workingDirectory.absolutePath,
                    useRoot = true,
                ),
            )
        }

        assertTrue(events.any {
            it is ZeroDpiRunnerEvent.Failed && it.message.contains("UID verification failed")
        })
    }

    private suspend fun collectRunnerEventsUntil(
        runner: ZeroDpiRunner,
        complete: (List<ZeroDpiRunnerEvent>) -> Boolean,
        block: suspend () -> Unit,
    ): List<ZeroDpiRunnerEvent> = coroutineScope {
        val events = mutableListOf<ZeroDpiRunnerEvent>()
        val collector = launch {
            runner.events().collect { event ->
                events += event
            }
        }
        try {
            yield()
            block()
            withTimeout(1_000) {
                while (!complete(events)) {
                    delay(10)
                }
            }
            events.toList()
        } finally {
            collector.cancel()
        }
    }

    private class RecordingProcessLauncher(
        private val process: Process,
    ) : ZeroDpiProcessLauncher {
        val commands = mutableListOf<List<String>>()
        val workingDirectories = mutableListOf<File>()

        override suspend fun start(command: List<String>, workingDirectory: File): Process {
            commands += command
            workingDirectories += workingDirectory
            return process
        }
    }

    private class FakeRootManager(
        private val launchProcess: Process = FakeProcess(),
    ) : RootManager {
        val launches = mutableListOf<RootHelperLaunchRequest>()

        override suspend fun isRootAvailable(): RootAvailability =
            error("Root availability is not used by this test.")

        override suspend fun requestRootFor(reason: String): RootAccessResult =
            error("Root request is not used by this test.")

        override suspend fun launchRootHelper(request: RootHelperLaunchRequest): RootProcessLaunchResult {
            launches += request
            return RootProcessLaunchResult.Started(
                process = launchProcess,
                pid = 1234L,
                command = listOf("su", "-c", request.executable.absolutePath),
            )
        }

        override suspend fun stopRootProcess(pid: Long): RootCommandResult =
            RootCommandResult(
                label = "kill -TERM $pid",
                command = listOf("su", "-c", "kill -TERM $pid"),
                exitCode = 0,
                stdout = "",
                stderr = "",
                timedOut = false,
            )

        override suspend fun runDiagnostics(firewallBackend: String): RootDiagnosticReport =
            error("Root diagnostics are not used by this test.")
    }

    private class FakeProcess(
        stdout: String = "",
        private val exitCode: Int = 0,
    ) : Process() {
        private val output = ByteArrayOutputStream()
        private val input = ByteArrayInputStream(stdout.toByteArray(Charsets.UTF_8))
        private var alive = true

        override fun getOutputStream(): OutputStream = output

        override fun getInputStream(): InputStream = input

        override fun getErrorStream(): InputStream =
            ByteArrayInputStream(ByteArray(0))

        override fun waitFor(): Int {
            alive = false
            return exitCode
        }

        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            alive = false
            return true
        }

        override fun exitValue(): Int {
            if (alive) {
                throw IllegalThreadStateException("Fake process is still alive.")
            }
            return exitCode
        }

        override fun destroy() {
            alive = false
        }

        override fun destroyForcibly(): Process {
            alive = false
            return this
        }

        override fun isAlive(): Boolean = alive
    }

    /**
     * Process double that stays alive until it is killed, so tests can model a
     * data plane that went silent without exiting.
     */
    private class HangingFakeProcess : Process() {
        private val output = ByteArrayOutputStream()
        private val input = ByteArrayInputStream(ByteArray(0))

        @Volatile
        private var alive = true

        override fun getOutputStream(): OutputStream = output

        override fun getInputStream(): InputStream = input

        override fun getErrorStream(): InputStream =
            ByteArrayInputStream(ByteArray(0))

        override fun waitFor(): Int {
            while (alive) {
                Thread.sleep(20)
            }
            return EXIT_CODE
        }

        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            val deadline = System.currentTimeMillis() + unit.toMillis(timeout)
            while (alive && System.currentTimeMillis() < deadline) {
                Thread.sleep(20)
            }
            return !alive
        }

        override fun exitValue(): Int {
            if (alive) {
                throw IllegalThreadStateException("Fake process is still alive.")
            }
            return EXIT_CODE
        }

        override fun destroy() {
            alive = false
        }

        override fun destroyForcibly(): Process {
            alive = false
            return this
        }

        override fun isAlive(): Boolean = alive

        private companion object {
            const val EXIT_CODE = 137
        }
    }
}
