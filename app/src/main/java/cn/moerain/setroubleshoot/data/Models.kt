package cn.moerain.setroubleshoot.data

/**
 * SELinux 安全上下文，例如 u:r:untrusted_app:s0:c512,c768
 */
data class SeContext(
    val user: String,
    val role: String,
    val type: String,
    val mls: String
) {
    val raw: String
        get() = if (mls.isBlank()) "$user:$role:$type" else "$user:$role:$type:$mls"

    companion object {
        fun parse(raw: String?): SeContext {
            if (raw.isNullOrBlank()) return SeContext("?", "?", "unknown", "")
            val parts = raw.split(':')
            return when {
                parts.size >= 4 -> SeContext(
                    user = parts[0],
                    role = parts[1],
                    type = parts[2],
                    mls = parts.drop(3).joinToString(":")
                )

                parts.size == 3 -> SeContext(parts[0], parts[1], parts[2], "")
                parts.size == 2 -> SeContext(parts[0], parts[1], "unknown", "")
                else -> SeContext("?", "?", raw, "")
            }
        }
    }
}

enum class Severity(val label: String) {
    INFO("提示"),
    WARNING("警告"),
    DANGER("危险")
}

enum class DenialSource(val label: String) {
    DMESG("dmesg"),
    LOGCAT("logcat"),
    AUDIT_LOG("audit.log"),
    PASTED("粘贴日志"),
    ALL("全部来源")
}

/**
 * 一条 SELinux AVC 拒绝记录。
 * 对应 setroubleshoot 中的 AVC / AuditRecord 概念。
 */
data class AvcEvent(
    val raw: String,
    val timestamp: Long? = null,
    val eventId: String? = null,
    val pid: Int? = null,
    val comm: String? = null,
    val exe: String? = null,
    val name: String? = null,
    val path: String? = null,
    val cwd: String? = null,
    val dev: String? = null,
    val ino: Long? = null,
    val port: String? = null,
    val scontext: SeContext,
    val tcontext: SeContext,
    val tclass: String,
    val perms: List<String>,
    val permissive: Boolean? = null,
    val granted: Boolean = false,
    val syscall: String? = null,
    val success: Boolean? = null,
    val source: String = "unknown"
) {
    val subject: String
        get() = comm ?: exe ?: scontext.type

    val targetPath: String
        get() = path ?: name ?: ""

    val targetDisplay: String
        get() = targetPath.ifBlank { tcontext.type }

    val isPermissive: Boolean
        get() = permissive == true || success == true

    /**
     * 用于合并同类告警的签名，对应 setroubleshoot 的 SEFaultSignature。
     */
    val signature: String
        get() = buildString {
            append(subject)
            append('|')
            append(scontext.type)
            append('|')
            append(tcontext.type)
            append('|')
            append(tclass)
            append('|')
            append(perms.sorted().joinToString(","))
        }

    val accessText: String
        get() = perms.joinToString(", ")

    fun policyRule(): String =
        "allow ${scontext.type} ${tcontext.type}:$tclass { ${perms.joinToString(" ")} };"
}

data class Suggestion(
    val title: String,
    val detail: String,
    val command: String? = null,
    val dangerous: Boolean = false,
    val requiresRoot: Boolean = true
)

data class Analysis(
    val ruleId: String,
    val summary: String,
    val description: String,
    val severity: Severity,
    val confidence: Int,
    val suggestions: List<Suggestion>,
    val policyRule: String,
    val falsePositiveHint: String? = null
)

data class AvcAlert(
    val signature: String,
    val events: List<AvcEvent>,
    val analysis: Analysis
) {
    val count: Int
        get() = events.size

    val representative: AvcEvent
        get() = events.last()

    val first: AvcEvent
        get() = events.first()

    val totalPerms: List<String>
        get() = events.flatMap { it.perms }.distinct().sorted()

    val id: String
        get() = signature
}

data class SelinuxStatus(
    val root: Boolean = false,
    val selinuxEnabled: Boolean = false,
    val enforcing: Boolean = false,
    val enforceKnown: Boolean = false,
    val modeText: String = "未知",
    val policyVersion: String? = null,
    val context: String? = null,
    val device: String = "",
    val androidVersion: String = "",
    val buildType: String = "",
    val suPath: String? = null,
    val bootSelinux: String? = null,
    val collectedAt: Long = 0L
) {
    val summary: String
        get() = modeText
}
