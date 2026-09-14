package com.meshelf.android.state

import android.content.Context
import java.io.File

/** Fixed app-private roots. No caller-selected or external-storage path is accepted. */
data class AppStatePaths private constructor(
    val root: File,
    val identityRecord: File,
    val stateDirectory: File,
) {
    companion object {
        fun from(context: Context): AppStatePaths {
            val root = File(context.noBackupFilesDir, "meshelf/v2")
            return AppStatePaths(
                root = root,
                identityRecord = File(root, "identity/installation-identity-v2.enc"),
                stateDirectory = File(root, "state"),
            )
        }
    }

    fun ensureStateDirectory(): File {
        require(stateDirectory.mkdirs() || stateDirectory.isDirectory) {
            "could not create app-private Rust state directory"
        }
        return stateDirectory.canonicalFile
    }
}
