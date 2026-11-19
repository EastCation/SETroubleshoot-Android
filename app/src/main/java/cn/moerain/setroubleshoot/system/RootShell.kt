package cn.moerain.setroubleshoot.system

import java.util.concurrent.TimeUnit

data class ShellResult(
    val success: Boolean,
    val output: String,
    val error: String,
    val exitCode: Int
) {
    val combined: String
        get() = listOf(output, error).filter { it.isNotBlank() }.joinToString("\n")
}

/**
 * 通过 su 执行命令。兼容常见 su 实现（Magisk / SuperSU / KernelSU）。
 */
object RootShell {

    private val rootCandidates = listOf(
        listOf("su", "-c"),
        listOf("su", "0", "sh", "-c")
    )

    @Volatile
    private var cachedPrefix: List<String>? = null

    fun isRootAvailable(): Boolean {
        val result = runAsRoot("id", timeoutSeconds = 12)
        return result.output.contains("uid=0") || result.error.contains("uid=0")
    }

    fun runAsRoot(command: String, timeoutSeconds: Long = 30): ShellResult {
        val cached = cachedPrefix
        if (cached != null) {
            val result = exec(cached + command, timeoutSeconds)
            if (result.success || result.output.isNotBlank()) return result
        }

        var last = ShellResult(false, "", "su 不可用（设备可能未 root）", -1)
        for (prefix in rootCandidates) {
            val result = exec(prefix + command, timeoutSeconds)
            if (result.success || result.output.isNotBlank()) {
                cachedPrefix = prefix
                return result
            }
            last = result
        }
        return last
    }

    fun runShell(command: String, timeoutSeconds: Long = 20): ShellResult =
        exec(listOf("sh", "-c", command), timeoutSeconds)

    private fun exec(parts: List<String>, timeoutSeconds: Long): ShellResult {
        var process: Process? = null
        return try {
            val builder = ProcessBuilder(parts).redirectErrorStream(false)
            val started = builder.start()
            process = started

            val out = StringBuilder()
            val err = StringBuilder()

            val outThread = Thread {
                runCatching {
                    started.inputStream.bufferedReader().use { reader ->
                        reader.forEachLine { out.appendLine(it) }
                    }
                }
            }.apply { isDaemon = true; start() }

            val errThread = Thread {
                runCatching {
                    started.errorStream.bufferedReader().use { reader ->
                        reader.forEachLine { err.appendLine(it) }
                    }
                }
            }.apply { isDaemon = true; start() }

            val finished = started.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                runCatching { started.destroyForcibly() }
                return ShellResult(false, out.toString(), "命令超时（${timeoutSeconds}s）", -2)
            }

            outThread.join(1500)
            errThread.join(1500)
            val code = started.exitValue()
            ShellResult(code == 0, out.toString(), err.toString(), code)
        } catch (e: Exception) {
            ShellResult(false, "", e.message ?: e.javaClass.simpleName, -1)
        } finally {
            runCatching { process?.destroy() }
        }
    }
}
