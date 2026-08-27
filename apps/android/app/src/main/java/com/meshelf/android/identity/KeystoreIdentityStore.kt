package com.meshelf.android.identity

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import com.meshelf.android.state.AppStatePaths
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val KEYSTORE = "AndroidKeyStore"
private const val KEY_ALIAS = "com.meshelf.identity.wrap.v1"
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val RECORD_VERSION = 1
private const val MAX_RECORD_BYTES = 4 * 1024
private const val MAX_CIPHERTEXT_BYTES = MAX_RECORD_BYTES + 64
private const val MAX_ENVELOPE_BYTES = 8 + 4 + 4 + 32 + 4 + MAX_CIPHERTEXT_BYTES
private val MAGIC = byteArrayOf(0x4d, 0x53, 0x48, 0x49, 0x44, 0x41, 0x4e, 0x44) // MSHIDAND
private val AAD = "meshelf/android/identity-wrap/v1".toByteArray(Charsets.UTF_8)

/**
 * Wraps an opaque Rust identity record. Kotlin never parses or signs with the
 * Ed25519 secret. Existing-record failures are fail-closed; callers must not
 * silently create a replacement identity.
 */
class KeystoreIdentityStore(context: Context) {
    private val recordFile = AtomicFile(AppStatePaths.from(context).identityRecord)

    @Synchronized
    fun load(): Result<ByteArray?> = runCatching {
        if (!recordFile.baseFile.exists()) return@runCatching null
        require(recordFile.baseFile.length() in 1..MAX_ENVELOPE_BYTES.toLong()) {
            "invalid identity envelope size"
        }
        val envelope = recordFile.readFully()
        require(envelope.size in 1..MAX_ENVELOPE_BYTES) { "invalid identity envelope size" }
        val input = DataInputStream(ByteArrayInputStream(envelope))
        val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
        require(magic.contentEquals(MAGIC)) { "identity envelope magic mismatch" }
        require(input.readInt() == RECORD_VERSION) { "identity envelope version mismatch" }
        val ivLength = input.readInt()
        require(ivLength in 12..32) { "invalid identity IV length" }
        val iv = ByteArray(ivLength).also { input.readFully(it) }
        val ciphertextLength = input.readInt()
        require(ciphertextLength in 1..MAX_CIPHERTEXT_BYTES) { "invalid identity ciphertext length" }
        val ciphertext = ByteArray(ciphertextLength).also { input.readFully(it) }
        require(input.available() == 0) { "trailing identity envelope bytes" }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, requireKey(), GCMParameterSpec(128, iv))
        cipher.updateAAD(AAD)
        cipher.doFinal(ciphertext).also { cleartext ->
            require(cleartext.size in 1..MAX_RECORD_BYTES) { "invalid Rust identity record size" }
        }
    }

    @Synchronized
    fun storeNew(record: ByteArray): Result<Unit> = runCatching {
        require(record.size in 1..MAX_RECORD_BYTES) { "invalid Rust identity record size" }
        require(!recordFile.baseFile.exists()) { "identity record already exists" }
        recordFile.baseFile.parentFile?.let { parent ->
            require(parent.mkdirs() || parent.isDirectory) { "could not create identity directory" }
        }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(AAD)
        val ciphertext = cipher.doFinal(record)
        require(ciphertext.size <= MAX_CIPHERTEXT_BYTES) { "identity ciphertext exceeds bound" }

        val outputBytes = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(MAGIC)
                output.writeInt(RECORD_VERSION)
                output.writeInt(cipher.iv.size)
                output.write(cipher.iv)
                output.writeInt(ciphertext.size)
                output.write(ciphertext)
            }
            bytes.toByteArray()
        }

        require(outputBytes.size <= MAX_ENVELOPE_BYTES) { "identity envelope exceeds bound" }

        val stream = recordFile.startWrite()
        try {
            stream.write(outputBytes)
            stream.fd.sync()
            recordFile.finishWrite(stream)
        } catch (error: Throwable) {
            recordFile.failWrite(stream)
            throw error
        }
    }

    /** Destructive operation; expose only behind explicit user confirmation. */
    @Synchronized
    fun resetExplicitly(): Result<Unit> = runCatching {
        recordFile.delete()
        val keyStore = keyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
    }

    private fun getOrCreateKey(): SecretKey {
        val existing = keyStore().getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    private fun requireKey(): SecretKey =
        (keyStore().getKey(KEY_ALIAS, null) as? SecretKey)
            ?: error("identity wrapping key is unavailable")

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
}
