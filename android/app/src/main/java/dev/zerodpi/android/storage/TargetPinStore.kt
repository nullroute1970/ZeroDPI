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
