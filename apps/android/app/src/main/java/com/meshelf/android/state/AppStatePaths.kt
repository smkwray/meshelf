package com.meshelf.android.state

import android.content.Context
import java.io.File

/** Fixed app-private roots. No caller-selected or external-storage path is accepted. */
data class AppStatePaths private constructor(
    val root: File,
    val identityRecord: File,
    val stateDirectory: File,
    val storeDirectory: File,
    val stagingDirectory: File,
) {
    companion object {
        fun from(context: Context): AppStatePaths {
            val root = File(context.noBackupFilesDir, "meshelf/v1")
            return AppStatePaths(
                root = root,
                identityRecord = File(root, "identity/installation-identity-v1.enc"),
                stateDirectory = File(root, "state"),
                storeDirectory = File(root, "store"),
                stagingDirectory = File(root, "staging"),
            )
        }
    }
}
