package dev.zerodpi.android.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.TargetPin
import dev.zerodpi.android.targetscan.TargetScanFiles
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

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
        assertNull(store.read(ZeroDpiProfile.DEFAULT_PROFILE_ID))
        store.write(ZeroDpiProfile.DEFAULT_PROFILE_ID, pin)
        assertEquals(pin, store.read(ZeroDpiProfile.DEFAULT_PROFILE_ID))
        store.clear(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        assertNull(store.read(ZeroDpiProfile.DEFAULT_PROFILE_ID))
    }

    private suspend fun clearPinFiles() {
        val repository = ProfileRepository(context)
        val paths = repository.filePaths(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        File(paths.profileDir, TargetScanFiles.PIN_FILE_NAME).delete()
    }
}
