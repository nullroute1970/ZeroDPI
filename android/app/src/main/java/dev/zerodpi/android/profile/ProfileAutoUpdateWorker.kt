package dev.zerodpi.android.profile

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dev.zerodpi.android.service.ZeroDpiRuntimeStateStore

class ProfileAutoUpdateWorker(
    appContext: Context,
    workerParams: WorkerParameters,
) : CoroutineWorker(appContext, workerParams) {
    override suspend fun doWork(): Result {
        val repository = ProfileRepository(applicationContext)
        val index = runCatching {
            repository.loadIndex()
        }.getOrElse {
            return Result.retry()
        }

        ProfileAutoUpdateScheduler.reconcile(applicationContext, index)

        val dueProfiles = ProfileAutoUpdatePolicy.dueProfiles(
            index = index,
            nowEpochMs = System.currentTimeMillis(),
        )
        if (dueProfiles.isEmpty()) {
            return Result.success()
        }

        if (ZeroDpiRuntimeStateStore.isRuntimeActive(applicationContext)) {
            dueProfiles.forEach { profile ->
                recordAutomaticFailure(
                    repository = repository,
                    profile = profile,
                    message = "Automatic update skipped because ZeroDPI is running.",
                )
            }
            return Result.success()
        }

        val updateManager = ProfileUpdateManager(
            profileRepository = repository,
            beforeApply = {
                check(!ZeroDpiRuntimeStateStore.isRuntimeActive(applicationContext)) {
                    "Automatic update skipped because ZeroDPI started running."
                }
            },
        )
        dueProfiles.forEach { profile ->
            if (ZeroDpiRuntimeStateStore.isRuntimeActive(applicationContext)) {
                recordAutomaticFailure(
                    repository = repository,
                    profile = profile,
                    message = "Automatic update skipped because ZeroDPI started running.",
                )
                return Result.success()
            }

            val validation = profile.remote.validateForUpdate()
            if (!validation.isValid) {
                recordAutomaticFailure(
                    repository = repository,
                    profile = profile,
                    message = validation.errors.joinToString("; ") { it.message }
                        .ifBlank { "Configure all three valid remote URLs before automatic updates." },
                )
                return@forEach
            }

            runCatching {
                updateManager.updateProfile(
                    profileId = profile.id,
                    mode = ProfileUpdateMode.Automatic,
                    remote = profile.remote,
                )
            }.onFailure { error ->
                recordAutomaticFailure(
                    repository = repository,
                    profile = profile,
                    message = error.message ?: "Automatic update failed.",
                )
            }
        }

        return Result.success()
    }

    private suspend fun recordAutomaticFailure(
        repository: ProfileRepository,
        profile: ZeroDpiProfile,
        message: String,
    ) {
        runCatching {
            repository.recordRemoteUpdateFailure(
                profileId = profile.id,
                mode = ProfileUpdateMode.Automatic,
                message = message,
                remote = profile.remote.takeIf { it.validate().isValid },
            )
        }
    }
}
