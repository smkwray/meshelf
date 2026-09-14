package com.meshelf.android.nativebridge

import java.lang.reflect.Method
import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins JNI ABI-8 between MeshelfNative and libmeshelf_android_bridge.so.
 */
class MeshelfNativeAbiTest {
    private val natives = mapOf(
        "nativeAbiVersion" to "()I",
        "nativeStart" to "(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;)V",
        "nativeStop" to "()V",
        "nativeCaptureCaptured" to "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V",
        "nativeCaptureDeclined" to "(Ljava/lang/String;Ljava/lang/String;)V",
        "nativeStatus" to "()Ljava/lang/String;",
        "nativeOpenPairingWindow" to "(J)V",
        "nativeClosePairingWindow" to "()V",
        "nativeConfirmPairing" to "(Ljava/lang/String;Ljava/lang/String;)V",
        "nativeRejectPairing" to "(Ljava/lang/String;)V",
        "nativeShelfSnapshot" to "()Ljava/lang/String;",
        "nativeRefreshOriginCatalogs" to "(J)Ljava/lang/String;",
        "nativeAnnounceText" to "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        "nativeAnnounceDocument" to "(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;)Ljava/lang/String;",
        "nativeReserveOrdinaryPhoto" to "(Ljava/lang/String;)Ljava/lang/String;",
        "nativeCommitOrdinaryPhoto" to "(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;",
        "nativeAbandonPhoto" to "(Ljava/lang/String;)V",
        "nativeActivate" to
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        "nativeInvalidatePlatformActions" to "()V",
        "nativeReportPlatformOutcome" to "(Ljava/lang/String;Ljava/lang/String;)V",
    )

    private val callbacks = mapOf(
        "onCaptureRequested" to "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V",
        "onCaptureWithdrawn" to "(Ljava/lang/String;Ljava/lang/String;)V",
        "onCaptureDelivered" to "(Ljava/lang/String;)V",
        "onPeerAdmitted" to "(Ljava/lang/String;)V",
        "onPairingCandidate" to "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V",
        "onPairingFinished" to "(Ljava/lang/String;Ljava/lang/String;)V",
        "loadInstallationIdentity" to "()[B",
        "storeInstallationIdentity" to "([B)V",
        "onShelfChanged" to "()V",
        "onPlatformDispatchPrepared" to "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        "onPlatformFileExportPrepared" to
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        "openDocumentSource" to "(Ljava/lang/String;J)I",
        "releaseDocumentLease" to "(Ljava/lang/String;)V",
    )

    private val declared: List<Method> = MeshelfNative::class.java.declaredMethods.filterNot { it.isSynthetic }

    @Test fun abiVersionIsEight() {
        assertEquals(8, MeshelfNative.ABI_VERSION)
    }

    @Test fun nativeMethodsAreExactlyTheAbi8Table() {
        val found = declared.filter { Modifier.isNative(it.modifiers) }
        assertEquals("a native method is overloaded", found.size, found.map { it.name }.toSet().size)
        assertEquals(natives, found.associate { it.name to descriptor(it) })
        found.forEach { method ->
            assertFalse("${method.name} must be an instance method", Modifier.isStatic(method.modifiers))
        }
    }

    @Test fun callbacksMatchTheAbi8Table() {
        callbacks.forEach { (name, expected) ->
            val matches = declared.filter { it.name == name }
            assertEquals("$name must be declared exactly once", 1, matches.size)
            val method = matches.single()
            assertTrue("$name must be public", Modifier.isPublic(method.modifiers))
            assertFalse("$name must be an instance method", Modifier.isStatic(method.modifiers))
            assertEquals(name, expected, descriptor(method))
        }
    }

    @Test fun everyEventCallbackIsPinned() {
        val eventCallbacks = declared
            .filter { Modifier.isPublic(it.modifiers) && it.name.startsWith("on") }
            .map { it.name }
            .toSet()
        assertEquals(callbacks.keys.filter { it.startsWith("on") }.toSet(), eventCallbacks)
    }

    @Test fun activateAndPlatformOutcomeAreNotMethodSynchronized() {
        // Regression: `@Synchronized` on activate held the Kotlin monitor while Rust waited for
        // reportPlatformOutcome, which needed the same monitor → 30s clipboard timeout.
        // Kotlin Result return types mangle JVM names; match by prefix.
        for (prefix in listOf(
            "activate",
            "reportPlatformOutcome",
            "invalidatePlatformActions",
            "commitOrdinaryPhoto",
        )) {
            val methods = declared.filter {
                it.name.startsWith(prefix) && !Modifier.isNative(it.modifiers)
            }
            assertTrue("$prefix must exist as a non-native method", methods.isNotEmpty())
            methods.forEach { method ->
                assertFalse(
                    "${method.name} must not be ACC_SYNCHRONIZED (re-enters during clipboard wait)",
                    Modifier.isSynchronized(method.modifiers),
                )
            }
        }
    }

    private fun descriptor(method: Method): String {
        val args = method.parameterTypes.joinToString("") { typeDescriptor(it) }
        return "($args)${typeDescriptor(method.returnType)}"
    }

    private fun typeDescriptor(type: Class<*>): String = when {
        type === java.lang.Void.TYPE -> "V"
        type === java.lang.Integer.TYPE -> "I"
        type === java.lang.Long.TYPE -> "J"
        type === java.lang.Boolean.TYPE -> "Z"
        type === java.lang.Byte.TYPE -> "B"
        type.isArray -> "[${typeDescriptor(type.componentType)}"
        else -> "L${type.name.replace('.', '/')};"
    }
}
