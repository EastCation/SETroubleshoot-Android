package cn.moerain.setroubleshoot.system

import cn.moerain.setroubleshoot.data.SelinuxStatus
import java.io.File

object SelinuxCollector {

    private val sectionRegex = Regex("""^@@(\d+)@@$""")
    private const val SECTION_COUNT = 9

    private val statusCommand = """
        echo '@@0@@'; getprop ro.product.model
        echo '@@1@@'; getprop ro.build.version.release
        echo '@@2@@'; getprop ro.build.type
        echo '@@3@@'; getprop ro.build.selinux
        echo '@@4@@'; getprop ro.boot.selinux
        echo '@@5@@'; getenforce 2>/dev/null
        echo '@@6@@'; cat /sys/fs/selinux/enforce 2>/dev/null
        echo '@@7@@'; cat /sys/fs/selinux/policyvers 2>/dev/null
        echo '@@8@@'; for p in /system/bin/su /system/xbin/su /sbin/su /su/bin/su; do [ -x "${'$'}p" ] && echo "${'$'}p"; done; command -v su 2>/dev/null
    """.trimIndent()

    fun collect(): SelinuxStatus {
        val root = RootShell.isRootAvailable()

        // 普通应用域（untrusted_app/runas_app）通常被禁止读取
        // getenforce 与 /sys/fs/selinux/enforce，此时必须借助 root。
        val result = if (root) {
            RootShell.runAsRoot(statusCommand)
        } else {
            RootShell.runShell(statusCommand)
        }

        val sections = splitSections(result.output)
        val model = sections.getOrElse(0) { "" }
        val androidVersion = sections.getOrElse(1) { "" }
        val buildType = sections.getOrElse(2) { "" }
        val buildSelinux = sections.getOrElse(3) { "" }
        val bootSelinux = sections.getOrElse(4) { "" }
        val getenforce = firstValidLine(sections.getOrElse(5) { "" })
        val enforceFile = firstValidLine(sections.getOrElse(6) { "" })
        val policyVersion = firstValidLine(sections.getOrElse(7) { "" })
        val suPath = sections.getOrElse(8) { "" }

        // 应用自身上下文直接在本进程读取，避免 root shell 返回 u:r:su:s0。
        val context = readAppContext()

        val fromGetenforce = when {
            getenforce.equals("Enforcing", ignoreCase = true) -> true
            getenforce.equals("Permissive", ignoreCase = true) -> false
            else -> null
        }
        val fromFile = when (enforceFile) {
            "1" -> true
            "0" -> false
            else -> null
        }
        val fromBoot = when {
            bootSelinux.equals("enforcing", ignoreCase = true) -> true
            bootSelinux.equals("permissive", ignoreCase = true) -> false
            else -> null
        }

        val enforceKnown = fromGetenforce != null || fromFile != null || fromBoot != null
        val enforcing = fromGetenforce ?: fromFile ?: fromBoot ?: false

        val selinuxEnabled = enforceKnown ||
            context?.contains(":") == true ||
            bootSelinux.contains("enforcing", ignoreCase = true) ||
            bootSelinux.contains("permissive", ignoreCase = true)

        val modeText = when {
            !selinuxEnabled -> "Disabled"
            !enforceKnown -> "状态未知"
            enforcing -> "Enforcing"
            else -> "Permissive"
        }

        return SelinuxStatus(
            root = root,
            selinuxEnabled = selinuxEnabled,
            enforcing = enforcing,
            enforceKnown = enforceKnown,
            modeText = modeText,
            policyVersion = policyVersion.ifBlank { null },
            context = context,
            device = model.ifBlank { "未知设备" },
            androidVersion = androidVersion.ifBlank { "未知" },
            buildType = buildType,
            suPath = suPath.lineSequence().firstOrNull { it.isNotBlank() },
            bootSelinux = buildSelinux.ifBlank { bootSelinux }.ifBlank { null },
            collectedAt = System.currentTimeMillis()
        )
    }

    private fun readAppContext(): String? = runCatching {
        File("/proc/self/attr/current")
            .readText()
            .trim()
            .trim('\u0000')
            .ifBlank { null }
    }.getOrNull()

    /**
     * 过滤掉 Permission denied / Couldn't / No such 等错误行。
     */
    private fun firstValidLine(value: String): String =
        value.lineSequence()
            .map { it.trim() }
            .firstOrNull { line ->
                line.isNotBlank() &&
                    !line.contains("Permission denied", ignoreCase = true) &&
                    !line.contains("Couldn't", ignoreCase = true) &&
                    !line.contains("No such", ignoreCase = true)
            }
            .orEmpty()

    private fun splitSections(output: String): List<String> {
        val result = MutableList(SECTION_COUNT) { "" }
        var current = -1
        val buffer = StringBuilder()

        output.lineSequence().forEach { line ->
            val match = sectionRegex.matchEntire(line.trim())
            if (match != null) {
                if (current in 0 until SECTION_COUNT) {
                    result[current] = buffer.toString().trim()
                }
                buffer.setLength(0)
                current = match.groupValues[1].toIntOrNull() ?: -1
            } else if (current in 0 until SECTION_COUNT) {
                buffer.appendLine(line)
            }
        }
        if (current in 0 until SECTION_COUNT) {
            result[current] = buffer.toString().trim()
        }
        return result
    }
}
