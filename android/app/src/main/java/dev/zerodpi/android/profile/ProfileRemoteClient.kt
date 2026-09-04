package dev.zerodpi.android.profile

import dev.zerodpi.android.runtime.contentLengthLongCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Locale

enum class ProfileRemoteFile(
    val fileName: String,
    val maxDownloadBytes: Long,
) {
    Config("config.toml", 512L * 1024L),
    SniList("sni_list.txt", 5L * 1024L * 1024L),
    IpList("ip_list.txt", 5L * 1024L * 1024L);

    fun urlFrom(remote: ProfileRemoteSettings): String =
        when (this) {
            Config -> remote.configUrl
            SniList -> remote.sniListUrl
            IpList -> remote.ipListUrl
        }
}

data class ProfileRemoteFileResult(
    val file: ProfileRemoteFile,
    val requestedUrl: String,
    val statusCode: Int? = null,
    val finalUrl: String = requestedUrl,
    val contentText: String? = null,
    val responseHeaders: Map<String, List<String>> = emptyMap(),
    val errorMessage: String? = null,
) {
    val isSuccess: Boolean
        get() = errorMessage == null && contentText != null
}

data class ProfileRemoteDownloadSet(
    val results: List<ProfileRemoteFileResult>,
) {
    val config: ProfileRemoteFileResult
        get() = resultFor(ProfileRemoteFile.Config)

    val sniList: ProfileRemoteFileResult
        get() = resultFor(ProfileRemoteFile.SniList)

    val ipList: ProfileRemoteFileResult
        get() = resultFor(ProfileRemoteFile.IpList)

    val isSuccess: Boolean
        get() = results.all { it.isSuccess }

    fun resultFor(file: ProfileRemoteFile): ProfileRemoteFileResult =
        results.firstOrNull { it.file == file }
            ?: error("Missing remote download result for ${file.fileName}.")
}

interface ProfileRemoteClient {
    suspend fun download(
        file: ProfileRemoteFile,
        url: String,
    ): ProfileRemoteFileResult

    suspend fun downloadAll(remote: ProfileRemoteSettings): ProfileRemoteDownloadSet =
        ProfileRemoteDownloadSet(
            results = ProfileRemoteFile.entries.map { file ->
                download(file = file, url = file.urlFrom(remote))
            },
        )
}

class HttpUrlConnectionProfileRemoteClient(
    private val connectTimeoutMillis: Int = DEFAULT_CONNECT_TIMEOUT_MILLIS,
    private val readTimeoutMillis: Int = DEFAULT_READ_TIMEOUT_MILLIS,
    private val maxRedirects: Int = DEFAULT_MAX_REDIRECTS,
    private val connectionFactory: (URL) -> HttpURLConnection = { url ->
        url.openConnection() as HttpURLConnection
    },
) : ProfileRemoteClient {
    override suspend fun download(
        file: ProfileRemoteFile,
        url: String,
    ): ProfileRemoteFileResult =
        withContext(Dispatchers.IO) {
            downloadBlocking(file = file, requestedUrl = url)
        }

    private fun downloadBlocking(
        file: ProfileRemoteFile,
        requestedUrl: String,
    ): ProfileRemoteFileResult {
        val initialUrl = parseHttpUrl(requestedUrl)
            ?: return errorResult(
                file = file,
                requestedUrl = requestedUrl,
                message = "${file.fileName} URL must be an absolute http or https URL.",
            )

        var currentUrl = initialUrl
        var redirects = 0

        while (true) {
            val connection = try {
                connectionFactory(currentUrl)
            } catch (error: IOException) {
                return errorResult(
                    file = file,
                    requestedUrl = requestedUrl,
                    finalUrl = currentUrl.toExternalForm(),
                    message = "Failed to open ${file.fileName}: ${error.actionableMessage()}",
                )
            }

            var statusCode: Int? = null
            var headers: Map<String, List<String>> = emptyMap()

            try {
                configure(connection)
                statusCode = connection.responseCode
                headers = responseHeaders(connection.headerFields)

                if (statusCode.isRedirectStatus()) {
                    val redirectUrl = resolveRedirectUrl(currentUrl, connection.getHeaderField("Location"))
                        ?: return errorResult(
                            file = file,
                            requestedUrl = requestedUrl,
                            statusCode = statusCode,
                            finalUrl = currentUrl.toExternalForm(),
                            responseHeaders = headers,
                            message = "Redirect for ${file.fileName} did not include a valid Location header.",
                        )

                    if (!redirectUrl.protocol.isSupportedHttpScheme()) {
                        return errorResult(
                            file = file,
                            requestedUrl = requestedUrl,
                            statusCode = statusCode,
                            finalUrl = redirectUrl.toExternalForm(),
                            responseHeaders = headers,
                            message = "Redirect for ${file.fileName} used an unsupported URL scheme.",
                        )
                    }

                    if (!currentUrl.protocol.equals(redirectUrl.protocol, ignoreCase = true)) {
                        return errorResult(
                            file = file,
                            requestedUrl = requestedUrl,
                            statusCode = statusCode,
                            finalUrl = redirectUrl.toExternalForm(),
                            responseHeaders = headers,
                            message = "Redirect for ${file.fileName} changed scheme from " +
                                "${currentUrl.protocol} to ${redirectUrl.protocol}.",
                        )
                    }

                    if (redirects >= maxRedirects) {
                        return errorResult(
                            file = file,
                            requestedUrl = requestedUrl,
                            statusCode = statusCode,
                            finalUrl = currentUrl.toExternalForm(),
                            responseHeaders = headers,
                            message = "Too many redirects while downloading ${file.fileName}.",
                        )
                    }

                    redirects += 1
                    currentUrl = redirectUrl
                    continue
                }

                if (statusCode !in HTTP_SUCCESS_RANGE) {
                    return errorResult(
                        file = file,
                        requestedUrl = requestedUrl,
                        statusCode = statusCode,
                        finalUrl = currentUrl.toExternalForm(),
                        responseHeaders = headers,
                        message = "HTTP $statusCode while downloading ${file.fileName}.",
                    )
                }

                val contentLength = connection.contentLengthLongCompat()
                if (contentLength == 0L) {
                    return errorResult(
                        file = file,
                        requestedUrl = requestedUrl,
                        statusCode = statusCode,
                        finalUrl = currentUrl.toExternalForm(),
                        responseHeaders = headers,
                        message = "${file.fileName} response was empty.",
                    )
                }
                if (contentLength > file.maxDownloadBytes) {
                    return errorResult(
                        file = file,
                        requestedUrl = requestedUrl,
                        statusCode = statusCode,
                        finalUrl = currentUrl.toExternalForm(),
                        responseHeaders = headers,
                        message = "${file.fileName} response is larger than the " +
                            "${file.maxDownloadBytes.toReadableSize()} limit.",
                    )
                }

                val contentBytes = connection.inputStream.use { input ->
                    input.readBytesLimitedTo(file.maxDownloadBytes)
                }
                if (contentBytes.isEmpty()) {
                    return errorResult(
                        file = file,
                        requestedUrl = requestedUrl,
                        statusCode = statusCode,
                        finalUrl = currentUrl.toExternalForm(),
                        responseHeaders = headers,
                        message = "${file.fileName} response was empty.",
                    )
                }

                return ProfileRemoteFileResult(
                    file = file,
                    requestedUrl = requestedUrl,
                    statusCode = statusCode,
                    finalUrl = currentUrl.toExternalForm(),
                    contentText = String(contentBytes, StandardCharsets.UTF_8),
                    responseHeaders = headers,
                )
            } catch (error: ResponseTooLargeException) {
                return errorResult(
                    file = file,
                    requestedUrl = requestedUrl,
                    statusCode = statusCode,
                    finalUrl = currentUrl.toExternalForm(),
                    responseHeaders = headers,
                    message = "${file.fileName} response exceeded the ${error.limit.toReadableSize()} limit.",
                )
            } catch (error: IOException) {
                return errorResult(
                    file = file,
                    requestedUrl = requestedUrl,
                    statusCode = statusCode,
                    finalUrl = currentUrl.toExternalForm(),
                    responseHeaders = headers,
                    message = "Failed to download ${file.fileName}: ${error.actionableMessage()}",
                )
            } finally {
                connection.disconnect()
            }
        }
    }

    private fun configure(connection: HttpURLConnection) {
        connection.instanceFollowRedirects = false
        connection.connectTimeout = connectTimeoutMillis
        connection.readTimeout = readTimeoutMillis
        connection.useCaches = false
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "text/plain, application/octet-stream, */*")
    }

    private fun parseHttpUrl(value: String): URL? {
        if (value.isBlank()) {
            return null
        }
        val uri = runCatching { URI(value) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase(Locale.US) ?: return null
        if (!uri.isAbsolute || uri.host.isNullOrBlank() || !scheme.isSupportedHttpScheme()) {
            return null
        }
        return runCatching { uri.toURL() }.getOrNull()
    }

    private fun resolveRedirectUrl(
        currentUrl: URL,
        location: String?,
    ): URL? {
        if (location.isNullOrBlank()) {
            return null
        }
        return runCatching {
            currentUrl.toURI().resolve(location).toURL()
        }.getOrNull()
    }

    private fun responseHeaders(headerFields: Map<String?, List<String>>?): Map<String, List<String>> =
        headerFields.orEmpty()
            .mapNotNull { (name, values) ->
                name?.let { it to values.toList() }
            }
            .toMap()

    private fun errorResult(
        file: ProfileRemoteFile,
        requestedUrl: String,
        statusCode: Int? = null,
        finalUrl: String = requestedUrl,
        responseHeaders: Map<String, List<String>> = emptyMap(),
        message: String,
    ): ProfileRemoteFileResult =
        ProfileRemoteFileResult(
            file = file,
            requestedUrl = requestedUrl,
            statusCode = statusCode,
            finalUrl = finalUrl,
            responseHeaders = responseHeaders,
            errorMessage = message,
        )

    private fun Int.isRedirectStatus(): Boolean =
        this == HttpURLConnection.HTTP_MOVED_PERM ||
            this == HttpURLConnection.HTTP_MOVED_TEMP ||
            this == HttpURLConnection.HTTP_SEE_OTHER ||
            this == HTTP_TEMPORARY_REDIRECT ||
            this == HTTP_PERMANENT_REDIRECT

    private fun String.isSupportedHttpScheme(): Boolean =
        lowercase(Locale.US) in SUPPORTED_SCHEMES

    private fun Long.toReadableSize(): String =
        if (this % (1024L * 1024L) == 0L) {
            "${this / (1024L * 1024L)} MiB"
        } else {
            "${this / 1024L} KiB"
        }

    private fun IOException.actionableMessage(): String =
        message?.takeIf { it.isNotBlank() } ?: javaClass.simpleName

    private fun java.io.InputStream.readBytesLimitedTo(limit: Long): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var totalBytes = 0L
        while (true) {
            val read = read(buffer)
            if (read == -1) {
                break
            }
            totalBytes += read
            if (totalBytes > limit) {
                throw ResponseTooLargeException(limit)
            }
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }

    private class ResponseTooLargeException(
        val limit: Long,
    ) : IOException()

    private companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_MILLIS = 10_000
        private const val DEFAULT_READ_TIMEOUT_MILLIS = 30_000
        private const val DEFAULT_MAX_REDIRECTS = 5
        private const val HTTP_TEMPORARY_REDIRECT = 307
        private const val HTTP_PERMANENT_REDIRECT = 308
        private val HTTP_SUCCESS_RANGE = 200..299
        private val SUPPORTED_SCHEMES = setOf("http", "https")
    }
}
