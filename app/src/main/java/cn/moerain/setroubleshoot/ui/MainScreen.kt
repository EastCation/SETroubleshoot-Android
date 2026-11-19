package cn.moerain.setroubleshoot.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.moerain.setroubleshoot.AppController
import cn.moerain.setroubleshoot.data.AvcAlert
import cn.moerain.setroubleshoot.data.DenialSource
import cn.moerain.setroubleshoot.data.Severity

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    controller: AppController,
    snackbarHost: SnackbarHostState,
    filter: Severity?,
    onFilterChange: (Severity?) -> Unit,
    onOpenAlert: (AvcAlert) -> Unit,
    onOpenPaste: () -> Unit
) {
    val context = LocalContext.current
    val filtered = remember(controller.alerts, filter) {
        if (filter == null) {
            controller.alerts
        } else {
            controller.alerts.filter { it.analysis.severity == filter }
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHost) },
        topBar = {
            TopAppBar(
                title = { Text("SELinux 排障") },
                actions = {
                    TextButton(
                        onClick = { controller.refreshStatus() },
                        enabled = !controller.loading
                    ) {
                        Text("刷新")
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
            item { StatusCard(controller, onOpenPaste) }
            item { SummaryRow(controller, context) }
            item { FilterRow(filter, onFilterChange) }

            if (controller.loading) {
                item { LinearProgressIndicator(modifier = Modifier.fillMaxWidth()) }
            }

            if (filtered.isEmpty()) {
                item { EmptyCard(controller) }
            } else {
                items(filtered, key = { it.id }) { alert ->
                    AlertCard(alert = alert, onClick = { onOpenAlert(alert) })
                }
            }
        }
    }
}

@Composable
private fun StatusCard(controller: AppController, onOpenPaste: () -> Unit) {
    val status = controller.status
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Badge(
                    text = status.modeText,
                    color = when {
                        !status.selinuxEnabled -> MaterialTheme.colorScheme.outline
                        !status.enforceKnown -> MaterialTheme.colorScheme.outline
                        status.enforcing -> MaterialTheme.colorScheme.primary
                        else -> MaterialTheme.colorScheme.tertiary
                    }
                )
                Spacer(Modifier.width(8.dp))
                Badge(
                    text = if (status.root) "root 可用" else "无 root",
                    color = if (status.root) severityColor(Severity.INFO)
                    else severityColor(Severity.DANGER)
                )
                Spacer(Modifier.weight(1f))
                Text(
                    text = "${status.device} · Android ${status.androidVersion}",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            status.context?.let {
                Text(
                    text = "当前上下文：$it",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }
            status.policyVersion?.let {
                Text("策略版本：$it", style = MaterialTheme.typography.bodySmall)
            }
            if (!status.enforceKnown) {
                Text(
                    text = if (status.root) {
                        "无法读取 SELinux 模式，请检查 root 授权后重试。"
                    } else {
                        "无法读取 SELinux 模式：普通应用域禁止读取 /sys/fs/selinux/enforce。" +
                            "请在已 root 的设备上使用，并授予 su 权限后点击刷新。"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = severityColor(Severity.WARNING)
                )
            }
            controller.currentAction.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall)
            }

            ScanButtons(controller, onOpenPaste)
        }
    }
}

@Composable
private fun ScanButtons(controller: AppController, onOpenPaste: () -> Unit) {
    val enabled = !controller.loading
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { controller.scan(DenialSource.DMESG) },
                modifier = Modifier.weight(1f),
                enabled = enabled
            ) {
                Text("扫描 dmesg")
            }
            Button(
                onClick = { controller.scan(DenialSource.LOGCAT) },
                modifier = Modifier.weight(1f),
                enabled = enabled
            ) {
                Text("扫描 logcat")
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { controller.scan(DenialSource.AUDIT_LOG) },
                modifier = Modifier.weight(1f),
                enabled = enabled
            ) {
                Text("audit.log")
            }
            OutlinedButton(
                onClick = onOpenPaste,
                modifier = Modifier.weight(1f)
            ) {
                Text("粘贴日志")
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { controller.scan(DenialSource.ALL) },
                modifier = Modifier.weight(1f),
                enabled = enabled
            ) {
                Text("扫描全部来源")
            }
            OutlinedButton(
                onClick = { controller.clearAlerts() },
                modifier = Modifier.weight(1f),
                enabled = !controller.loading && controller.alerts.isNotEmpty()
            ) {
                Text("清空")
            }
        }
    }
}

@Composable
private fun SummaryRow(
    controller: AppController,
    context: android.content.Context
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard("AVC 总数", controller.totalEvents.toString(), Modifier.weight(1f))
            StatCard("告警类别", controller.alerts.size.toString(), Modifier.weight(1f))
            StatCard(
                "危险",
                controller.alerts.count { it.analysis.severity == Severity.DANGER }.toString(),
                Modifier.weight(1f)
            )
        }
        Text(
            text = controller.lastScanInfo,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = {
                    controller.copy(
                        context,
                        controller.buildSummaryReport(),
                        "汇总报告已复制"
                    )
                },
                modifier = Modifier.weight(1f),
                enabled = controller.alerts.isNotEmpty()
            ) {
                Text("复制汇总")
            }
            OutlinedButton(
                onClick = {
                    controller.copy(
                        context,
                        controller.buildPolicyRules(),
                        "全部策略规则已复制"
                    )
                },
                modifier = Modifier.weight(1f),
                enabled = controller.alerts.isNotEmpty()
            ) {
                Text("复制策略")
            }
        }
    }
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier = Modifier) {
    ElevatedCard(modifier = modifier) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value, style = MaterialTheme.typography.headlineSmall)
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun FilterRow(filter: Severity?, onFilterChange: (Severity?) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FilterChip(
            selected = filter == null,
            onClick = { onFilterChange(null) },
            label = { Text("全部") }
        )
        Severity.entries.forEach { severity ->
            FilterChip(
                selected = filter == severity,
                onClick = { onFilterChange(severity) },
                label = { Text(severity.label) }
            )
        }
    }
}

@Composable
private fun AlertCard(alert: AvcAlert, onClick: () -> Unit) {
    val event = alert.representative
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Badge(alert.analysis.severity.label, severityColor(alert.analysis.severity))
                Spacer(Modifier.width(8.dp))
                Text("×${alert.count}", style = MaterialTheme.typography.labelMedium)
                Spacer(Modifier.weight(1f))
                Text(
                    "置信度 ${alert.analysis.confidence}%",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                text = alert.analysis.summary,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = "${event.scontext.type} → ${event.tcontext.type}:${event.tclass}",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            Text(
                text = event.accessText,
                style = MaterialTheme.typography.bodySmall
            )
            if (event.targetPath.isNotBlank()) {
                Text(
                    text = "目标：${event.targetPath}",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Text(
                text = "规则 ${alert.analysis.ruleId}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun EmptyCard(controller: AppController) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("没有可显示的 AVC 告警", style = MaterialTheme.typography.titleMedium)
            Text(
                text = if (controller.alerts.isEmpty()) {
                    "点击上方按钮扫描 dmesg、logcat 或 audit.log，也可以粘贴日志进行分析。\n\n" +
                        "提示：读取其他进程的 AVC 需要 root，且 SELinux 需要处于 Enforcing 才会产生拒绝记录。"
                } else {
                    "当前筛选条件下没有告警，切换筛选条件试试。"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
