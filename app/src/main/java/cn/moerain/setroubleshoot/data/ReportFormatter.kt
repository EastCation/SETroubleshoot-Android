package cn.moerain.setroubleshoot.data

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 生成与 sealert 类似的可读报告。
 */
object ReportFormatter {

    fun formatAlert(alert: AvcAlert, status: SelinuxStatus): String {
        val event = alert.representative
        val analysis = alert.analysis

        return buildString {
            appendLine("SELinux 访问拒绝报告")
            appendLine("========================")
            appendLine("摘要：${analysis.summary}")
            appendLine()
            appendLine("发生了什么：")
            appendLine(analysis.description)
            appendLine()
            appendLine("级别：${analysis.severity.label}    置信度：${analysis.confidence}%    规则：${analysis.ruleId}")
            appendLine("发生次数：${alert.count}")
            val latest = event.timestamp
            if (latest != null && latest > 0) {
                appendLine("最近时间：${formatTime(latest)}")
            }
            appendLine()
            appendLine("附加信息：")
            appendLine("  源上下文   : ${event.scontext.raw}")
            appendLine("  目标上下文 : ${event.tcontext.raw}")
            appendLine("  源         : ${event.subject}")
            appendLine("  源路径     : ${event.exe ?: "未知"}")
            appendLine("  目标对象   : ${event.targetDisplay} [ ${event.tclass} ]")
            appendLine("  权限       : ${event.perms.joinToString(" ")}")
            if (event.port != null) appendLine("  端口       : ${event.port}")
            if (status.device.isNotBlank() || status.androidVersion.isNotBlank()) {
                appendLine("  设备       : ${status.device} (Android ${status.androidVersion})")
            }
            appendLine("  SELinux    : ${status.modeText}")
            if (status.context != null) appendLine("  当前上下文 : ${status.context}")
            if (status.policyVersion != null) appendLine("  策略版本   : ${status.policyVersion}")
            appendLine()
            appendLine("建议：")
            analysis.suggestions.forEachIndexed { index, suggestion ->
                appendLine("  ${index + 1}. ${suggestion.title}")
                suggestion.detail.lineSequence().forEach { line ->
                    appendLine("     $line")
                }
                suggestion.command?.let { appendLine("     命令：$it") }
                if (suggestion.dangerous) appendLine("     ⚠ 该操作有风险，可能削弱系统安全性。")
            }
            appendLine()
            appendLine("策略规则：")
            appendLine("  ${analysis.policyRule}")
            appendLine()
            analysis.falsePositiveHint?.let {
                appendLine("误报提示：")
                appendLine("  $it")
                appendLine()
            }
            appendLine("原始审计消息：")
            val rawLines = alert.events.map { it.raw }.distinct()
            rawLines.take(20).forEach { appendLine("  $it") }
            if (rawLines.size > 20) {
                appendLine("  ... 其余 ${rawLines.size - 20} 条相同签名的消息已省略")
            }
            appendLine()
        }
    }

    fun formatSummary(alerts: List<AvcAlert>, status: SelinuxStatus): String {
        val totalEvents = alerts.sumOf { it.count }
        val danger = alerts.count { it.analysis.severity == Severity.DANGER }
        val warning = alerts.count { it.analysis.severity == Severity.WARNING }
        val info = alerts.count { it.analysis.severity == Severity.INFO }
        return buildString {
            appendLine("SELinux 排障汇总")
            appendLine("================")
            appendLine("设备：${status.device} (Android ${status.androidVersion})")
            appendLine("SELinux：${status.modeText}    策略版本：${status.policyVersion ?: "未知"}")
            appendLine("root：${if (status.root) "可用" else "不可用"}")
            appendLine("AVC 总数：$totalEvents    告警类别：${alerts.size}")
            appendLine("  危险：$danger    警告：$warning    提示：$info")
            appendLine()
            alerts.forEachIndexed { index, alert ->
                val event = alert.representative
                appendLine("${index + 1}. [${alert.analysis.severity.label}] ${alert.analysis.summary}")
                appendLine("   ${event.scontext.type} -> ${event.tcontext.type}:${event.tclass} ${event.accessText}")
                if (event.targetPath.isNotBlank()) appendLine("   目标：${event.targetPath}")
                appendLine("   次数：${alert.count}    规则：${alert.analysis.ruleId}")
                appendLine()
            }
            val rules = alerts.map { it.analysis.policyRule }.distinct()
            if (rules.isNotEmpty()) {
                appendLine("策略规则（去重）")
                rules.forEach { appendLine("  $it") }
            }
        }
    }

    private fun formatTime(millis: Long): String {
        val formatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        return formatter.format(Date(millis))
    }
}
