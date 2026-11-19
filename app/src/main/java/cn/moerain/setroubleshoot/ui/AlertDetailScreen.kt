package cn.moerain.setroubleshoot.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.moerain.setroubleshoot.AppController
import cn.moerain.setroubleshoot.data.AvcAlert
import cn.moerain.setroubleshoot.data.AvcEvent
import cn.moerain.setroubleshoot.data.Severity
import cn.moerain.setroubleshoot.data.Suggestion
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AlertDetailScreen(
    controller: AppController,
    alert: AvcAlert,
    snackbarHost: SnackbarHostState,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var pendingCommand by remember { mutableStateOf<Suggestion?>(null) }
    val report = remember(alert, controller.status) { controller.buildAlertReport(alert) }
    val event = alert.representative
    val analysis = alert.analysis

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHost) },
        topBar = {
            TopAppBar(
                title = { Text("告警详情") },
                navigationIcon = {
                    TextButton(onClick = onBack) { Text("返回") }
                },
                actions = {
                    TextButton(onClick = { controller.share(context, report, "SELinux 报告") }) {
                        Text("分享")
                    }
                    TextButton(onClick = { controller.copy(context, report, "完整报告已复制") }) {
                        Text("复制报告")
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item { HeaderCard(alert) }
            item { DescriptionCard(analysis.description) }
            item { ContextCard(event) }
            item {
                PolicyCard(analysis.policyRule) {
                    controller.copy(context, analysis.policyRule, "策略规则已复制")
                }
            }

            item { SectionTitle("建议与修复") }
            itemsIndexed(analysis.suggestions) { index, suggestion ->
                SuggestionCard(
                    index = index + 1,
                    suggestion = suggestion,
                    enabled = !controller.loading,
                    onCopy = { controller.copy(context, it, "命令已复制") },
                    onRun = { item ->
                        if (item.dangerous) {
                            pendingCommand = item
                        } else {
                            item.command?.let { controller.runCommand(it, "执行命令") }
                        }
                    }
                )
            }

            analysis.falsePositiveHint?.let { hint ->
                item { HintCard(hint) }
            }

            item {
                RawCard(alert) {
                    controller.copy(
                        context,
                        alert.events.joinToString("\n") { it.raw },
                        "原始日志已复制"
                    )
                }
            }
            item { SummaryActions(controller, report, context) }
        }
    }

    val pending = pendingCommand
    if (pending != null && pending.command != null) {
        AlertDialog(
            onDismissRequest = { pendingCommand = null },
            title = { Text("确认执行高风险命令") },
            text = {
                Text(
                    "即将执行：\n\n${pending.command}\n\n" +
                        "该操作可能降低设备安全性或导致系统异常。请先确认已了解其作用，并确保可以恢复。"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val command = pending.command
                    pendingCommand = null
                    controller.runCommand(command, "执行命令")
                }) {
                    Text("仍然执行")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingCommand = null }) { Text("取消") }
            }
        )
    }
}

@Composable
private fun HeaderCard(alert: AvcAlert) {
    val analysis = alert.analysis
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Badge(analysis.severity.label, severityColor(analysis.severity))
                Spacer(Modifier.width(8.dp))
                Text("置信度 ${analysis.confidence}%", style = MaterialTheme.typography.labelMedium)
                Spacer(Modifier.weight(1f))
                Text("×${alert.count}", style = MaterialTheme.typography.titleSmall)
            }
            Text(
                text = analysis.summary,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "规则：${analysis.ruleId}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = "签名：${alert.signature}",
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun DescriptionCard(description: String) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            SectionTitle("发生了什么")
            Text(description, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun ContextCard(event: AvcEvent) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            SectionTitle("上下文")
            InfoRow("源上下文", event.scontext.raw)
            InfoRow("目标上下文", event.tcontext.raw)
            InfoRow("源", event.subject)
            InfoRow("源路径", event.exe ?: "未知")
            InfoRow("目标对象", "${event.targetDisplay} [ ${event.tclass} ]")
            InfoRow("权限", event.perms.joinToString(" "))
            if (event.port != null) InfoRow("端口", event.port)
            if (event.pid != null) InfoRow("PID", event.pid.toString())
            if (event.syscall != null) InfoRow("syscall", event.syscall)
            event.timestamp?.takeIf { it > 0 }?.let {
                InfoRow("时间", formatTimestamp(it))
            }
            InfoRow("来源", event.source)
        }
    }
}

@Composable
private fun PolicyCard(rule: String, onCopy: () -> Unit) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SectionTitle("策略规则")
            Text(
                "确认访问确有必要时，可把下面规则加入设备 sepolicy；Magisk 设备也可用 magiskpolicy 临时注入。",
                style = MaterialTheme.typography.bodySmall
            )
            CodeBlock(rule)
            TextButton(onClick = onCopy) { Text("复制规则") }
        }
    }
}

@Composable
private fun SuggestionCard(
    index: Int,
    suggestion: Suggestion,
    enabled: Boolean,
    onCopy: (String) -> Unit,
    onRun: (Suggestion) -> Unit
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Badge("#$index", MaterialTheme.colorScheme.outline)
                Spacer(Modifier.width(8.dp))
                Text(
                    text = suggestion.title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
            }
            Text(suggestion.detail, style = MaterialTheme.typography.bodySmall)
            if (suggestion.dangerous) {
                Text(
                    "⚠ 高风险操作",
                    style = MaterialTheme.typography.labelSmall,
                    color = severityColor(Severity.DANGER)
                )
            }
            suggestion.command?.let { command ->
                CodeBlock(command)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { onCopy(command) }) { Text("复制命令") }
                    TextButton(onClick = { onRun(suggestion) }, enabled = enabled) {
                        Text(if (suggestion.dangerous) "执行（需确认）" else "执行")
                    }
                }
            }
        }
    }
}

@Composable
private fun HintCard(hint: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.tertiaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text("误报提示", style = MaterialTheme.typography.titleSmall)
            Text(hint, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun RawCard(alert: AvcAlert, onCopy: () -> Unit) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SectionTitle("原始审计消息")
            CodeBlock(
                alert.events.map { it.raw }.distinct().take(50).joinToString("\n")
            )
            TextButton(onClick = onCopy) { Text("复制原始日志") }
        }
    }
}

@Composable
private fun SummaryActions(
    controller: AppController,
    report: String,
    context: android.content.Context
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            onClick = { controller.copy(context, report, "完整报告已复制") },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("复制完整报告")
        }
        OutlinedButton(
            onClick = { controller.share(context, report, "SELinux 报告") },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("分享报告")
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            text = label,
            modifier = Modifier.width(88.dp),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value.ifBlank { "—" },
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
private fun CodeBlock(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small,
        modifier = Modifier.fillMaxWidth()
    ) {
        SelectionContainer {
            Text(
                text = text,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(12.dp)
            )
        }
    }
}

private fun formatTimestamp(millis: Long): String {
    val formatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
    return formatter.format(Date(millis))
}
