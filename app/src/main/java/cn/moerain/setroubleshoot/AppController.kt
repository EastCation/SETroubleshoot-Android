package cn.moerain.setroubleshoot

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import cn.moerain.setroubleshoot.data.AvcAlert
import cn.moerain.setroubleshoot.data.AvcAnalyzer
import cn.moerain.setroubleshoot.data.AvcParser
import cn.moerain.setroubleshoot.data.DenialSource
import cn.moerain.setroubleshoot.data.ReportFormatter
import cn.moerain.setroubleshoot.data.SelinuxStatus
import cn.moerain.setroubleshoot.system.DenialCollector
import cn.moerain.setroubleshoot.system.RootShell
import cn.moerain.setroubleshoot.system.SelinuxCollector

/**
 * 应用状态与后台任务调度。
 */
class AppController {

    var status by mutableStateOf(SelinuxStatus())
        private set

    var alerts by mutableStateOf<List<AvcAlert>>(emptyList())
        private set

    var loading by mutableStateOf(false)
        private set

    var currentAction by mutableStateOf("")
        private set

    var message by mutableStateOf<String?>(null)
        private set

    var lastScanInfo by mutableStateOf("尚未扫描")
        private set

    var totalEvents by mutableStateOf(0)
        private set

    private val main = Handler(Looper.getMainLooper())

    fun showMessage(text: String) {
        message = text
    }

    fun consumeMessage() {
        message = null
    }

    /**
     * 首次启动：读取 SELinux 状态并扫描 dmesg。
     */
    fun bootstrap() {
        if (loading) return
        loading = true
        currentAction = "初始化"
        io {
            val collected = runCatching { SelinuxCollector.collect() }.getOrDefault(status)
            val text = runCatching { DenialCollector.collect(DenialSource.DMESG) }.getOrElse { "" }
            applyText(text, DenialSource.DMESG, collected)
        }
    }

    fun refreshStatus() {
        if (loading) return
        loading = true
        currentAction = "读取 SELinux 状态"
        io {
            val collected = runCatching { SelinuxCollector.collect() }.getOrElse { status }
            main.post {
                status = collected
                loading = false
                currentAction = ""
                message = if (collected.root) {
                    "SELinux 状态已刷新"
                } else {
                    "未获取到 root 权限，仅能读取有限信息"
                }
            }
        }
    }

    fun scan(source: DenialSource) {
        if (loading) return
        loading = true
        currentAction = "扫描 ${source.label}"
        io {
            val collected = if (status.collectedAt == 0L) {
                runCatching { SelinuxCollector.collect() }.getOrDefault(status)
            } else {
                status
            }
            val text = runCatching { DenialCollector.collect(source) }.getOrElse { "" }
            applyText(text, source, collected)
        }
    }

    fun analyzePasted(text: String) {
        if (text.isBlank()) {
            showMessage("日志内容为空")
            return
        }
        if (loading) return
        loading = true
        currentAction = "分析粘贴日志"
        io { applyText(text, DenialSource.PASTED, status) }
    }

    fun clearAlerts() {
        alerts = emptyList()
        totalEvents = 0
        lastScanInfo = "尚未扫描"
        showMessage("列表已清空")
    }

    fun runCommand(command: String, label: String = "执行命令") {
        if (loading) return
        loading = true
        currentAction = label
        io {
            val result = RootShell.runAsRoot(command)
            main.post {
                loading = false
                currentAction = ""
                message = when {
                    result.success -> "已执行：$command"
                    result.error.isNotBlank() ->
                        "执行失败：${result.error.trim().lineSequence().firstOrNull()}"

                    else -> "执行失败（exit ${result.exitCode}）"
                }
            }
        }
    }

    fun copy(context: Context, text: String, toast: String) {
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        manager.setPrimaryClip(ClipData.newPlainText("SELinux", text))
        showMessage(toast)
    }

    fun share(context: Context, text: String, title: String) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, title)
            putExtra(Intent.EXTRA_TEXT, text)
        }
        context.startActivity(Intent.createChooser(intent, "分享报告"))
    }

    fun buildAlertReport(alert: AvcAlert): String =
        ReportFormatter.formatAlert(alert, status)

    fun buildSummaryReport(): String =
        ReportFormatter.formatSummary(alerts, status)

    fun buildPolicyRules(): String =
        alerts.map { it.analysis.policyRule }.distinct().joinToString("\n")

    private fun applyText(text: String, source: DenialSource, baseStatus: SelinuxStatus) {
        val events = AvcParser.parseLog(text, source.label).filter { !it.granted }
        val grouped = events.groupBy { it.signature }
        val list = grouped.values.map { group ->
            val sorted = group.sortedBy { it.timestamp ?: 0L }
            AvcAlert(
                signature = group.first().signature,
                events = sorted,
                analysis = AvcAnalyzer.analyze(sorted.last(), baseStatus)
            )
        }.sortedWith(
            compareByDescending<AvcAlert> { it.analysis.severity.ordinal }
                .thenByDescending { it.count }
                .thenBy { it.analysis.summary }
        )

        main.post {
            status = baseStatus
            alerts = list
            totalEvents = events.size
            loading = false
            currentAction = ""
            lastScanInfo = "${source.label} · ${events.size} 条 AVC / ${list.size} 类告警"
            message = when {
                events.isEmpty() && source == DenialSource.PASTED ->
                    "未从粘贴内容中解析到 AVC 拒绝记录"

                events.isEmpty() ->
                    "未发现 AVC 记录（${source.label}）。请确认设备已 root 且 SELinux 处于 Enforcing。"

                else -> "已分析 ${events.size} 条 AVC，合并为 ${list.size} 类告警"
            }
        }
    }

    private fun io(block: () -> Unit) {
        Thread {
            runCatching(block).onFailure { error ->
                main.post {
                    loading = false
                    currentAction = ""
                    message = "错误：${error.message ?: error.javaClass.simpleName}"
                }
            }
        }.apply { isDaemon = true }.start()
    }
}
