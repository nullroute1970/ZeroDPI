package dev.zerodpi.android.runtime

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit

class SuRootManagerTest {
    @Test
    fun requestRootForUsesSuAndCachesGrantedSession() = runBlocking {
        val executor = FakeRootProcessExecutor(
            FakeResponse(stdout = "0\n", exitCode = 0),
        )
        val manager = SuRootManager(executor)

        val first = manager.requestRootFor("starting sni_spoof with wrong_seq")
        val second = manager.requestRootFor("starting sni_spoof with wrong_seq again")

        assertEquals(RootAccessState.Granted, first.state)
        assertEquals(RootAccessState.Granted, second.state)
        assertTrue(second.message.contains("already granted"))
        assertEquals(listOf(listOf("su", "-c", "id -u")), executor.commands)
    }

    @Test
    fun requestRootForSurfacesSuExitStatusAndStderr() = runBlocking {
        val executor = FakeRootProcessExecutor(
            FakeResponse(stderr = "permission denied\n", exitCode = 1),
        )
        val manager = SuRootManager(executor)

        val result = manager.requestRootFor("starting proxy_scan with wrong_seq")

        assertEquals(RootAccessState.Denied, result.state)
        assertTrue(result.message.contains("exit 1"))
        assertTrue(result.message.contains("permission denied"))
        assertEquals("permission denied\n", result.commandResult?.stderr)
    }

    @Test
    fun launchRootHelperBuildsOnlyTheTypedHelperCommand() = runBlocking {
        val executor = FakeRootProcessExecutor(FakeResponse(exitCode = 0))
        val manager = SuRootManager(executor)
        val workingDirectory = File("/data/user/0/dev.zerodpi.android/files/zero dpi")

        val runtimeDirectory = File("/data/user/0/dev.zerodpi.android/files/helper session")
        val result = manager.launchRootHelper(
            RootHelperLaunchRequest(
                executable = File("/data/app/libzerodpi_root_helper_exec.so"),
                socketPath = File(runtimeDirectory, "control.sock"),
                sessionFile = File(runtimeDirectory, "session.proof"),
                expectedAppUid = 10123,
                parentPid = 4321,
                workingDirectory = workingDirectory,
            ),
        )

        assertTrue(result is RootProcessLaunchResult.Started)
        assertEquals(
            listOf(
                "su",
                "-c",
                "cd '${workingDirectory.absolutePath}' && " +
                    "exec '${File("/data/app/libzerodpi_root_helper_exec.so").absolutePath}' --socket " +
                    "'${File(runtimeDirectory, "control.sock").absolutePath}' --expected-uid 10123 " +
                    "--session-file '${File(runtimeDirectory, "session.proof").absolutePath}' --parent-pid 4321",
            ),
            executor.commands.single(),
        )
        assertEquals(listOf<File?>(null), executor.workingDirectories)
    }

    @Test
    fun runDiagnosticsReportsFirewallAndNfqueueChecks() = runBlocking {
        val executor = FakeRootProcessExecutor(
            FakeResponse(stdout = "0\n", exitCode = 0),
            FakeResponse(stdout = "/system/bin/iptables\n", exitCode = 0),
            FakeResponse(stderr = "which: nft: not found\n", exitCode = 1),
            FakeResponse(stdout = "/proc/net/netfilter/nfnetlink_queue readable\n", exitCode = 0),
        )
        val manager = SuRootManager(executor)

        val report = manager.runDiagnostics("iptables")

        assertEquals(RootAccessState.Granted, report.rootAccess.state)
        assertEquals(3, report.checks.size)
        assertTrue(report.checks[0].diagnosticLine().contains("/system/bin/iptables"))
        assertTrue(report.checks[1].diagnosticLine().contains("exit 1"))
        assertTrue(report.checks[1].diagnosticLine().contains("which: nft: not found"))
        assertTrue(report.checks[2].diagnosticLine().contains("nfnetlink_queue readable"))
        assertTrue(report.skipped.any { it.contains("dry startup skipped") })
        assertEquals(
            listOf(
                listOf("su", "-c", "id -u"),
                listOf("su", "-c", "which iptables"),
                listOf("su", "-c", "which nft"),
                listOf(
                    "su",
                    "-c",
                    "if [ -r /proc/net/netfilter/nfnetlink_queue ]; then " +
                        "echo /proc/net/netfilter/nfnetlink_queue readable; " +
                        "else echo /proc/net/netfilter/nfnetlink_queue unavailable; fi; " +
                        "if [ -d /sys/module/nfnetlink_queue ] || [ -d /sys/module/xt_NFQUEUE ]; then " +
                        "echo NFQUEUE module path visible; " +
                        "else echo NFQUEUE module path not visible; fi",
                ),
            ),
            executor.commands,
        )
    }

    private data class FakeResponse(
        val stdout: String = "",
        val stderr: String = "",
        val exitCode: Int = 0,
    )

    private class FakeRootProcessExecutor(
        vararg responses: FakeResponse,
    ) : RootProcessExecutor {
        private val responses = ArrayDeque(responses.toList())
        val commands = mutableListOf<List<String>>()
        val workingDirectories = mutableListOf<File?>()

        override fun start(
            command: List<String>,
            workingDirectory: File?,
            redirectErrorStream: Boolean,
        ): Process {
            commands += command
            workingDirectories += workingDirectory
            val response = responses.removeFirstOrNull()
                ?: error("No fake response for command $command")
            return FakeProcess(response, redirectErrorStream)
        }
    }

    private class FakeProcess(
        response: FakeResponse,
        redirectErrorStream: Boolean,
    ) : Process() {
        private val output = ByteArrayOutputStream()
        private val stdout = if (redirectErrorStream) {
            response.stdout + response.stderr
        } else {
            response.stdout
        }
        private val stderr = if (redirectErrorStream) "" else response.stderr
        private val exitCode = response.exitCode
        private var destroyed = false

        override fun getOutputStream(): OutputStream = output

        override fun getInputStream(): InputStream =
            ByteArrayInputStream(stdout.toByteArray(Charsets.UTF_8))

        override fun getErrorStream(): InputStream =
            ByteArrayInputStream(stderr.toByteArray(Charsets.UTF_8))

        override fun waitFor(): Int = exitCode

        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = true

        override fun exitValue(): Int = exitCode

        override fun destroy() {
            destroyed = true
        }

        override fun destroyForcibly(): Process {
            destroyed = true
            return this
        }
    }
}
