package com.meshelf.android.nativebridge

object MeshelfNative {
    private val loadResult: Result<Unit> = runCatching {
        System.loadLibrary("meshelf_android_bridge")
    }

    @JvmStatic
    private external fun nativeAbiVersion(): Int

    fun abiVersion(): Result<Int> = loadResult.mapCatching {
        val version = nativeAbiVersion()
        require(version == 1) { "unsupported native ABI $version (expected 1)" }
        version
    }
}
