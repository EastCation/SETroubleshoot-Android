package cn.moerain.setroubleshoot.system

import cn.moerain.setroubleshoot.data.DenialSource

/**
 * 从设备收集 AVC 文本日志。
 */
object DenialCollector {

    private const val DMESG_COMMAND = "dmesg 2>/dev/null"
    private const val LOGCAT_COMMAND = "logcat -d -b all -v threadtime -t 8000 2>/dev/null"
    private const val AUDIT_LOG_COMMAND =
        "for f in /data/misc/audit/audit.log /data/misc/audit/audit.log.1 " +
            "/data/misc/audit/audit.log.2 /var/log/audit/audit.log; " +
            "do [ -f \"\$f\" ] && tail -n 8000 \"\$f\"; done"

    fun collect(source: DenialSource): String {
        return when (source) {
            DenialSource.DMESG -> collectDmesg()
            DenialSource.LOGCAT -> collectLogcat()
            DenialSource.AUDIT_LOG -> collectAuditLog()
            DenialSource.ALL -> buildString {
                appendLine(collectDmesg())
                appendLine(collectLogcat())
                appendLine(collectAuditLog())
            }

            DenialSource.PASTED -> ""
        }
    }

    fun collectDmesg(): String = RootShell.runAsRoot(DMESG_COMMAND).output

    fun collectLogcat(): String = RootShell.runAsRoot(LOGCAT_COMMAND).output

    fun collectAuditLog(): String = RootShell.runAsRoot(AUDIT_LOG_COMMAND).output
}
