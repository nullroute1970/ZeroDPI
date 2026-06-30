package dev.zerodpi.android.profile

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.FileNotFoundException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

class ProfileRemoteClientTest {
    @Test
    fun downloadsSameSchemeRedirectAndCapturesHeaders() = runBlocking {
        val factory = FakeConnectionFactory(
            "https://example.com/config.toml" to redirect("https://cdn.example.com/config.toml"),
            "https://cdn.example.com/config.toml" to ok(
                body = "MODE = \"sni_spoof\"\n",
                headers = mapOf("ETag" to listOf("\"abc\"")),
            ),
        )
        val client = HttpUrlConnectionProfileRemoteClient(connectionFactory = factory::open)

        val result = client.download(ProfileRemoteFile.Config, "https://example.com/config.toml")

        assertTrue(result.isSuccess)
        assertEquals(200, result.statusCode)
        assertEquals("https://cdn.example.com/config.toml", result.finalUrl)
        assertEquals("MODE = \"sni_spoof\"\n", result.contentText)
        assertEquals(listOf("\"abc\""), result.responseHeaders["ETag"])
        assertEquals(
            listOf("https://example.com/config.toml", "https://cdn.example.com/config.toml"),
            factory.openedUrls,
        )
    }

    @Test
    fun rejectsCrossSchemeRedirects() = runBlocking {
        val factory = FakeConnectionFactory(
            "https://example.com/config.toml" to redirect("http://example.com/config.toml"),
        )
        val client = HttpUrlConnectionProfileRemoteClient(connectionFactory = factory::open)

        val result = client.download(ProfileRemoteFile.Config, "https://example.com/config.toml")

        assertFalse(result.isSuccess)
        assertEquals(302, result.statusCode)
        assertEquals("http://example.com/config.toml", result.finalUrl)
        assertTrue(result.errorMessage.orEmpty().contains("changed scheme"))
        assertEquals(listOf("https://example.com/config.toml"), factory.openedUrls)
    }

    @Test
    fun rejectsUnsupportedSchemesBeforeOpeningConnection() = runBlocking {
        var openedConnection = false
        val client = HttpUrlConnectionProfileRemoteClient(
            connectionFactory = { url ->
                openedConnection = true
                error("Unexpected connection for $url")
            },
        )

        val result = client.download(ProfileRemoteFile.Config, "ftp://example.com/config.toml")

        assertFalse(result.isSuccess)
        assertFalse(openedConnection)
        assertTrue(result.errorMessage.orEmpty().contains("http or https"))
    }

    @Test
    fun rejectsEmptyRequiredResponses() = runBlocking {
        val factory = FakeConnectionFactory(
            "https://example.com/sni_list.txt" to ok(body = ""),
        )
        val client = HttpUrlConnectionProfileRemoteClient(connectionFactory = factory::open)

        val result = client.download(ProfileRemoteFile.SniList, "https://example.com/sni_list.txt")

        assertFalse(result.isSuccess)
        assertEquals(200, result.statusCode)
        assertNull(result.contentText)
        assertTrue(result.errorMessage.orEmpty().contains("empty"))
    }

    @Test
    fun rejectsContentLengthAboveFileLimit() = runBlocking {
        val factory = FakeConnectionFactory(
            "https://example.com/config.toml" to ok(
                body = "not read",
                contentLength = ProfileRemoteFile.Config.maxDownloadBytes + 1L,
            ),
        )
        val client = HttpUrlConnectionProfileRemoteClient(connectionFactory = factory::open)

        val result = client.download(ProfileRemoteFile.Config, "https://example.com/config.toml")

        assertFalse(result.isSuccess)
        assertEquals(200, result.statusCode)
        assertTrue(result.errorMessage.orEmpty().contains("512 KiB"))
    }

    @Test
    fun rejectsStreamThatExceedsFileLimitWithoutContentLength() = runBlocking {
        val oversizedBody = ByteArray(ProfileRemoteFile.Config.maxDownloadBytes.toInt() + 1) {
            'a'.code.toByte()
        }
        val factory = FakeConnectionFactory(
            "https://example.com/config.toml" to FakeResponse(
                statusCode = 200,
                body = oversizedBody,
                contentLength = -1L,
            ),
        )
        val client = HttpUrlConnectionProfileRemoteClient(connectionFactory = factory::open)

        val result = client.download(ProfileRemoteFile.Config, "https://example.com/config.toml")

        assertFalse(result.isSuccess)
        assertEquals(200, result.statusCode)
        assertTrue(result.errorMessage.orEmpty().contains("512 KiB"))
    }

    @Test
    fun downloadAllReturnsAResultForEachProfileFile() = runBlocking {
        val remote = ProfileRemoteSettings(
            configUrl = "https://example.com/config.toml",
            sniListUrl = "https://example.com/sni_list.txt",
            ipListUrl = "https://example.com/ip_list.txt",
        )
        val client = object : ProfileRemoteClient {
            override suspend fun download(
                file: ProfileRemoteFile,
                url: String,
            ): ProfileRemoteFileResult =
                ProfileRemoteFileResult(
                    file = file,
                    requestedUrl = url,
                    statusCode = 200,
                    contentText = "${file.fileName}\n",
                )
        }

        val result = client.downloadAll(remote)

        assertTrue(result.isSuccess)
        assertEquals("config.toml\n", result.config.contentText)
        assertEquals("sni_list.txt\n", result.sniList.contentText)
        assertEquals("ip_list.txt\n", result.ipList.contentText)
    }

    private class FakeConnectionFactory(
        vararg responses: Pair<String, FakeResponse>,
    ) {
        private val responsesByUrl = responses.toMap()
        val openedUrls = mutableListOf<String>()

        fun open(url: URL): HttpURLConnection {
            val urlText = url.toExternalForm()
            openedUrls += urlText
            return FakeHttpURLConnection(
                url = url,
                response = responsesByUrl[urlText] ?: FakeResponse(statusCode = 404),
            )
        }
    }

    private class FakeHttpURLConnection(
        url: URL,
        private val response: FakeResponse,
    ) : HttpURLConnection(url) {
        override fun connect() = Unit

        override fun disconnect() = Unit

        override fun usingProxy(): Boolean = false

        override fun getResponseCode(): Int = response.statusCode

        override fun getHeaderFields(): Map<String?, List<String>> =
            buildMap {
                response.headers.forEach { (name, values) ->
                    put(name, values)
                }
            }

        override fun getHeaderField(name: String?): String? =
            response.headers.entries.firstOrNull { (headerName, _) ->
                headerName.equals(name, ignoreCase = true)
            }?.value?.firstOrNull()

        override fun getInputStream(): InputStream {
            if (response.statusCode !in 200..299) {
                throw FileNotFoundException(url.toExternalForm())
            }
            return ByteArrayInputStream(response.body)
        }

        override fun getContentLengthLong(): Long =
            response.contentLength ?: response.body.size.toLong()
    }

    private data class FakeResponse(
        val statusCode: Int,
        val body: ByteArray = ByteArray(0),
        val headers: Map<String, List<String>> = emptyMap(),
        val contentLength: Long? = null,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is FakeResponse) return false
            return statusCode == other.statusCode &&
                body.contentEquals(other.body) &&
                headers == other.headers &&
                contentLength == other.contentLength
        }

        override fun hashCode(): Int {
            var result = statusCode
            result = 31 * result + body.contentHashCode()
            result = 31 * result + headers.hashCode()
            result = 31 * result + (contentLength?.hashCode() ?: 0)
            return result
        }
    }

    private fun ok(
        body: String,
        headers: Map<String, List<String>> = emptyMap(),
        contentLength: Long? = null,
    ): FakeResponse =
        FakeResponse(
            statusCode = 200,
            body = body.toByteArray(StandardCharsets.UTF_8),
            headers = headers,
            contentLength = contentLength,
        )

    private fun redirect(location: String): FakeResponse =
        FakeResponse(
            statusCode = 302,
            headers = mapOf("Location" to listOf(location)),
        )
}
