package cn.moerain.setroubleshoot.data

import java.util.Locale

/**
 * Android 场景下的 AVC 分析器。
 *
 * setroubleshoot 通过 /usr/share/setroubleshoot/plugins 下的插件解释拒绝原因；
 * Android 没有 Fedora 的插件体系，这里用一组内置规则实现同样的目标：
 * 解释拒绝原因、判断严重程度、给出可执行的修复/诊断建议，并生成 allow 策略规则。
 */
object AvcAnalyzer {

    private val fileClasses = setOf(
        "file", "dir", "lnk_file", "sock_file", "fifo_file", "chr_file", "blk_file"
    )

    private val networkClasses = setOf(
        "tcp_socket", "udp_socket", "rawip_socket", "packet_socket", "socket",
        "netlink_route_socket", "netlink_firewall_socket", "netlink_xfrm_socket",
        "netlink_selinux_socket", "netlink_audit_socket", "netlink_connector_socket",
        "netlink_netfilter_socket", "netlink_generic_socket", "netlink_scsitransport_socket",
        "netlink_rdma_socket", "netlink_crypto_socket"
    )

    fun analyze(event: AvcEvent, status: SelinuxStatus): Analysis {
        val primary = grantedRule(event)
            ?: permissiveRule(event, status)
            ?: rootRule(event)
            ?: binderRule(event)
            ?: serviceManagerRule(event)
            ?: propertyRule(event)
            ?: capabilityRule(event)
            ?: networkRule(event)
            ?: unixSocketRule(event)
            ?: processRule(event)
            ?: filesystemRule(event)
            ?: fileRule(event)
            ?: genericRule(event)

        val suggestions = (primary.suggestions + genericSuggestions(event))
            .distinctBy { it.title + "|" + it.command }

        return primary.copy(
            suggestions = suggestions,
            policyRule = event.policyRule(),
            falsePositiveHint = primary.falsePositiveHint ?: falsePositiveHint(event)
        )
    }

    private fun grantedRule(event: AvcEvent): Analysis? {
        if (!event.granted) return null
        return Analysis(
            ruleId = "granted",
            summary = "该访问已被允许（granted）",
            description = "内核记录了一条 granted AVC，说明当前策略允许该访问。" +
                "如果它出现在拒绝排查列表中，多半是因为 policy 中开启了 auditallow。",
            severity = Severity.INFO,
            confidence = 99,
            suggestions = emptyList(),
            policyRule = event.policyRule()
        )
    }

    private fun permissiveRule(event: AvcEvent, status: SelinuxStatus): Analysis? {
        // 只有在确认当前处于 Permissive 时才按系统级 permissive 处理；
        // 无 root 时可能读不到 enforce 状态，不能据此误判为 Permissive。
        val systemPermissive = status.selinuxEnabled && status.enforceKnown && !status.enforcing
        if (!event.isPermissive && !systemPermissive) return null
        val reason = when {
            event.isPermissive && event.scontext.type.isNotBlank() ->
                "进程的源域 ${event.scontext.type} 处于 permissive 模式，内核只记录而未阻止访问。"

            systemPermissive -> "系统当前处于 Permissive 模式，所有 AVC 都会记录但不会真正阻止访问。"
            else -> "该 AVC 未被实际阻止。"
        }
        return Analysis(
            ruleId = "permissive",
            summary = "访问未被实际拒绝（Permissive）",
            description = "$reason\n如果切换到 Enforcing 后功能仍然正常，通常无需处理；" +
                "如果切换后立即失败，才需要按下面的建议修复策略或标签。",
            severity = Severity.INFO,
            confidence = 99,
            suggestions = listOf(
                Suggestion(
                    title = "切换到 Enforcing 验证",
                    detail = "临时把 SELinux 切换到 Enforcing 后重新触发操作，" +
                        "确认该访问是否真的会影响功能。排查完成后可用 setenforce 1 保持强制模式。",
                    command = "setenforce 1",
                    dangerous = false
                )
            ),
            policyRule = event.policyRule(),
            falsePositiveHint = "permissive 记录不代表访问被阻止，不应盲目添加 allow 规则。"
        )
    }

    private fun rootRule(event: AvcEvent): Analysis? {
        val sourceType = event.scontext.type.lowercase(Locale.US)
        val subject = event.subject.lowercase(Locale.US)
        val isRootTool = sourceType.contains("magisk") || sourceType == "su" ||
            sourceType.startsWith("su_") || subject == "su" || subject == "magisk" ||
            subject == "magiskd" || subject.contains("magisk")
        if (!isRootTool) return null
        return Analysis(
            ruleId = "root_tool",
            summary = "root / Magisk 工具的访问被拒绝",
            description = "被拒绝的进程属于 su/Magisk 或其他 root 工具域。" +
                "这类拒绝常见于 Magisk 模块挂载文件、修改系统属性或访问其他应用数据时，" +
                "通常不会影响普通应用，但可能导致模块功能异常。",
            severity = Severity.WARNING,
            confidence = 85,
            suggestions = listOf(
                Suggestion(
                    title = "使用 magiskpolicy 临时放行",
                    detail = "在 Magisk 环境中可以临时注入策略（重启后失效）：",
                    command = "magiskpolicy --live \"${event.policyRule()}\"",
                    dangerous = true
                ),
                Suggestion(
                    title = "写入 Magisk 模块 sepolicy.rule",
                    detail = "把规则放入模块目录的 sepolicy.rule 文件并重启，可持久生效：" +
                        "\n/data/adb/modules/<模块名>/sepolicy.rule\n${event.policyRule()}",
                    command = null
                ),
                Suggestion(
                    title = "更新 Magisk 或模块",
                    detail = "很多 su/magisk 拒绝是新系统版本策略变化导致的，" +
                        "优先升级 Magisk 与相关模块，而不是直接放宽策略。",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun binderRule(event: AvcEvent): Analysis? {
        if (event.tclass != "binder") return null
        return Analysis(
            ruleId = "binder",
            summary = "Binder 调用被拒绝",
            description = "源域 ${event.scontext.type} 缺少对目标 Binder 类型 ${event.tcontext.type} 的 " +
                "${event.accessText} 权限。Binder 目标类型由 service_contexts 决定，" +
                "常见于跨应用/系统服务调用或自定义 AIDL 服务。",
            severity = Severity.WARNING,
            confidence = 82,
            suggestions = listOf(
                Suggestion(
                    title = "确认服务上下文",
                    detail = "检查目标服务是否在 service_contexts 中声明正确，并用下面的命令确认服务存在：",
                    command = "service list | grep ${event.tcontext.type}",
                    dangerous = false
                ),
                Suggestion(
                    title = "优先通过公开 API 访问",
                    detail = "普通应用通常不应直接调用系统内部 Binder 服务。" +
                        "请确认使用的是公开 SDK API，而不是反射/隐藏 API。",
                    command = null
                ),
                Suggestion(
                    title = "添加 binder allow 规则",
                    detail = "设备源码中在源域的 .te 文件加入规则并重新编译策略：\n${event.policyRule()}",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun serviceManagerRule(event: AvcEvent): Analysis? {
        if (event.tclass != "service_manager") return null
        val add = event.perms.any { it == "add" }
        return Analysis(
            ruleId = "service_manager",
            summary = if (add) "注册系统服务被拒绝" else "查找系统服务被拒绝",
            description = "service_manager 控制 servicemanager 的 find/add/list 操作。" +
                "注册服务需要目标服务类型在 service_contexts 中声明；" +
                "查找服务则需要源域拥有对应 service_manager 权限。",
            severity = Severity.WARNING,
            confidence = 84,
            suggestions = listOf(
                Suggestion(
                    title = "查看已注册服务",
                    detail = "确认服务名与类型是否正确：",
                    command = "service list",
                    dangerous = false
                ),
                Suggestion(
                    title = "在设备策略中添加规则",
                    detail = "把下面的 allow 规则加入源域 .te，并为服务声明 service_contexts：\n${event.policyRule()}",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun propertyRule(event: AvcEvent): Analysis? {
        if (event.tclass != "property_service") return null
        val set = event.perms.any { it == "set" }
        return Analysis(
            ruleId = "property_service",
            summary = if (set) "设置系统属性被拒绝" else "读取系统属性被拒绝",
            description = "Android 属性由 property_contexts 按前缀分配标签。" +
                "源域 ${event.scontext.type} 没有对 ${event.tcontext.type} 类型属性的 " +
                "${event.accessText} 权限。应用一般只能写自己命名空间下的属性，" +
                "或通过系统服务间接修改。",
            severity = Severity.WARNING,
            confidence = 85,
            suggestions = listOf(
                Suggestion(
                    title = "确认属性前缀",
                    detail = "用下面的命令查看属性的上下文；只有属于本域的属性前缀才应允许写入：",
                    command = "getprop -Z | head -n 50",
                    dangerous = false
                ),
                Suggestion(
                    title = "改用公开接口",
                    detail = "应用不应直接修改系统属性。请通过 Settings、系统服务或应用私有配置实现。",
                    command = null
                ),
                Suggestion(
                    title = "添加属性允许规则",
                    detail = "设备源码中添加 property_contexts 与 allow 规则：\n${event.policyRule()}",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun capabilityRule(event: AvcEvent): Analysis? {
        if (event.tclass != "capability" && event.tclass != "capability2") return null
        val notes = event.perms.joinToString("；") { perm ->
            val text = capabilityNotes[perm]
            if (text != null) "$perm（$text）" else perm
        }
        val isApp = isAppDomain(event.scontext.type)
        return Analysis(
            ruleId = "capability",
            summary = "能力（capability）使用被拒绝",
            description = "源域 ${event.scontext.type} 缺少能力：$notes。\n" +
                if (isApp) {
                    "普通应用无法获得这些内核能力；应改用系统服务或受支持的 API。"
                } else {
                    "系统/特权域需要在策略中显式授予对应 capability。"
                },
            severity = if (isApp) Severity.WARNING else Severity.INFO,
            confidence = 80,
            suggestions = listOf(
                Suggestion(
                    title = "避免申请高权限能力",
                    detail = "优先通过系统服务完成操作；确需特权时再为专用系统域授予能力。",
                    command = null
                ),
                Suggestion(
                    title = "添加 capability 规则",
                    detail = "设备源码中添加规则并重新编译策略：\n${event.policyRule()}",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun networkRule(event: AvcEvent): Analysis? {
        if (event.tclass !in networkClasses) return null
        val port = event.port?.toIntOrNull()
        val privilegedPort = event.perms.any { it == "name_bind" } && port != null && port in 1..1023
        val summary = when {
            event.perms.any { it == "name_bind" } -> "网络端口绑定被拒绝"
            event.perms.any { it == "name_connect" } -> "网络连接被拒绝"
            event.perms.any { it == "node_bind" } -> "网络接口绑定被拒绝"
            else -> "网络 socket 访问被拒绝"
        }
        val description = buildString {
            append("源域 ${event.scontext.type} 对目标类型 ${event.tcontext.type} 的 ")
            append(event.tclass)
            append(" 缺少 ")
            append(event.accessText)
            append(" 权限。")
            if (event.port != null) append("\n端口：${event.port}")
            if (privilegedPort) {
                append("\n注意：目标端口小于 1024，属于特权端口，普通应用/非特权域通常无法绑定。")
            }
        }
        val suggestions = mutableListOf<Suggestion>()
        if (privilegedPort) {
            suggestions += Suggestion(
                title = "改用非特权端口",
                detail = "把服务监听端口改为 1024 以上，可避免端口标签与特权端口限制。",
                command = null
            )
        }
        suggestions += Suggestion(
            title = "检查端口标签",
            detail = "Android 使用 port_contexts 为端口分配类型。确认端口是否属于本域允许的类型：",
            command = "cat /system/etc/selinux/*/port_contexts 2>/dev/null",
            dangerous = false
        )
        suggestions += Suggestion(
            title = "添加网络 allow 规则",
            detail = "设备源码中添加规则：\n${event.policyRule()}",
            command = null
        )
        return Analysis(
            ruleId = "network",
            summary = summary,
            description = description,
            severity = Severity.WARNING,
            confidence = 80,
            suggestions = suggestions,
            policyRule = event.policyRule()
        )
    }

    private fun unixSocketRule(event: AvcEvent): Analysis? {
        if (event.tclass != "unix_stream_socket" && event.tclass != "unix_dgram_socket") return null
        return Analysis(
            ruleId = "unix_socket",
            summary = "Unix socket 通信被拒绝",
            description = "源域 ${event.scontext.type} 无法对 ${event.tcontext.type} 执行 " +
                "${event.accessText}。unix socket 的 connectto 权限需要通信双方都有允许规则，" +
                "常见于应用与系统服务、属性服务或 init 的 socket 通信。",
            severity = Severity.WARNING,
            confidence = 78,
            suggestions = listOf(
                Suggestion(
                    title = "检查 socket 路径",
                    detail = "查看目标 socket 文件标签，确认是否挂载/创建在正确的目录：",
                    command = "ls -Z /dev/socket 2>/dev/null",
                    dangerous = false
                ),
                Suggestion(
                    title = "添加 socket allow 规则",
                    detail = "设备源码中添加规则：\n${event.policyRule()}",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun processRule(event: AvcEvent): Analysis? {
        if (event.tclass != "process" && event.tclass != "process2") return null
        val ptrace = event.perms.any { it == "ptrace" }
        return Analysis(
            ruleId = "process",
            summary = if (ptrace) "进程 ptrace 调试被拒绝" else "进程信号/调度访问被拒绝",
            description = "源域 ${event.scontext.type} 对 ${event.tcontext.type} 进程缺少 " +
                "${event.accessText} 权限。\n" +
                if (ptrace) {
                    "ptrace 可用于读取/篡改其他进程内存，普通应用之间默认互相禁止，这是重要的安全边界。"
                } else {
                    "常见的 process 权限包括 signal、getsched、getattr 等；" +
                        "跨域操作需要显式 allow。"
                },
            severity = if (ptrace) Severity.DANGER else Severity.WARNING,
            confidence = 82,
            suggestions = listOf(
                Suggestion(
                    title = "避免跨进程调试",
                    detail = "绝大多数应用场景不应需要 ptrace 其他进程。" +
                        "如果用于调试，请使用 debuggable 版本与 IDE，而不是放宽生产策略。",
                    command = null
                ),
                Suggestion(
                    title = "仅为受信任域添加规则",
                    detail = "确属系统组件需求时，在设备源码中添加最小规则：\n${event.policyRule()}",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun filesystemRule(event: AvcEvent): Analysis? {
        if (event.tclass != "filesystem") return null
        return Analysis(
            ruleId = "filesystem",
            summary = "文件系统挂载/重挂载被拒绝",
            description = "源域 ${event.scontext.type} 对文件系统缺少 ${event.accessText} 权限。" +
                "在 Android 上挂载操作通常只允许 init、vold 或 Magisk 等特权域执行。",
            severity = Severity.WARNING,
            confidence = 82,
            suggestions = listOf(
                Suggestion(
                    title = "通过 init/vold 完成挂载",
                    detail = "应用无法直接挂载文件系统。请通过 StorageManager、MediaStore 或由 init 脚本完成。",
                    command = null
                ),
                Suggestion(
                    title = "检查挂载选项",
                    detail = "如果确实需要在启动时挂载，请在 init .rc 或 Magisk 模块中完成，并声明正确的 context。",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun fileRule(event: AvcEvent): Analysis? {
        if (event.tclass !in fileClasses) return null

        val sourceType = event.scontext.type
        val targetType = event.tcontext.type
        val path = event.targetPath
        val perms = event.perms.map { it.lowercase(Locale.US) }.toSet()
        val isApp = isAppDomain(sourceType)
        val isSystemPath = path.startsWith("/system/") || path.startsWith("/vendor/") ||
            path.startsWith("/product/") || path.startsWith("/system_ext/") ||
            path.startsWith("/odm/")
        val isAppData = path.startsWith("/data/data/") || path.startsWith("/data/user/") ||
            path.startsWith("/data/user_de/") || path.startsWith("/data/misc/")
        val isShared = path.startsWith("/sdcard") || path.startsWith("/storage/") ||
            path.startsWith("/mnt/media_rw") || path.startsWith("/mnt/user/")
        val isKernelInterface = path.startsWith("/proc/") || path.startsWith("/sys/") ||
            path.startsWith("/dev/")
        val executes = perms.contains("execute") || perms.contains("execute_no_trans")

        var ruleId = "file_access"
        var summary = "文件/目录访问被拒绝"
        var confidence = 74
        var severity = Severity.WARNING
        val suggestions = mutableListOf<Suggestion>()
        val description = StringBuilder()

        when {
            targetType == "default_context" || targetType == "unlabeled" ||
                targetType == "rootfs" || targetType.endsWith("_unlabeled") -> {
                ruleId = "unlabeled_file"
                summary = "目标文件缺少正确的 SELinux 标签"
                confidence = 88
                description.append(
                    "目标对象的类型是 $targetType，通常说明文件没有被打上正确的标签，" +
                        "或者位于不支持标签的文件系统上。恢复默认标签通常即可解决。"
                )
                if (path.startsWith("/")) {
                    suggestions += Suggestion(
                        title = "恢复默认文件标签",
                        detail = "对该路径执行 restorecon，并重新检查标签：",
                        command = "restorecon -Rv ${quote(path)}",
                        dangerous = false
                    )
                }
            }

            isApp && isAppData && !isAppDataLabel(targetType) -> {
                ruleId = "app_data_label"
                summary = "应用数据目录标签异常"
                confidence = 85
                description.append(
                    "目标路径位于应用数据目录，但类型是 $targetType，而不是 app_data_file 等数据文件类型。" +
                        "这通常是文件被错误创建/复制导致的标签问题。"
                )
                if (path.startsWith("/")) {
                    suggestions += Suggestion(
                        title = "恢复应用数据标签",
                        detail = "对应用数据目录执行 restorecon：",
                        command = "restorecon -Rv ${quote(path)}",
                        dangerous = false
                    )
                }
            }

            isApp && isShared -> {
                ruleId = "shared_storage"
                summary = "访问共享存储被拒绝"
                description.append(
                    "Android 10+ 对共享存储访问有严格限制，应用应使用 MediaStore、SAF 或应用专属目录，" +
                        "而不是直接按路径读写 /sdcard。当前拒绝是预期的沙箱行为。"
                )
                confidence = 86
                suggestions += Suggestion(
                    title = "使用 MediaStore / SAF",
                    detail = "通过 MediaStore API 或 Storage Access Framework 访问共享文件，避免直接路径访问。",
                    command = null
                )
            }

            isApp && executes -> {
                ruleId = "exec_wx"
                summary = "应用尝试执行文件被拒绝"
                description.append(
                    "Android 10+ 禁止应用从可写目录执行代码（W^X 限制）。" +
                        "应用只能执行 APK 内 lib 目录下的原生库，或通过 app_process 运行受支持的代码。"
                )
                severity = Severity.DANGER
                confidence = 85
                suggestions += Suggestion(
                    title = "改用原生库",
                    detail = "把需要执行的代码编译为 .so 放入应用的 jniLibs/lib 目录，" +
                        "系统会以正确标签挂载并允许执行。",
                    command = null
                )
            }

            isApp && isSystemPath -> {
                ruleId = "system_partition"
                summary = if (targetType.endsWith("_file") || targetType == "system_file") {
                    "普通应用访问系统分区被拒绝"
                } else {
                    "应用访问系统分区被拒绝"
                }
                confidence = 82
                description.append(
                    "这是 Android 沙箱的预期行为：普通应用的域不能随意读取/写入 /system、/vendor 等分区。" +
                        "如果应用功能异常，应改用公开 API 或把资源随 APK 打包，而不是放宽系统分区策略。"
                )
                if (perms.any { it == "write" || it == "append" || it == "create" }) {
                    description.append("\n系统分区通常是只读的（dm-verity），即使 SELinux 放行也无法持久写入。")
                }
                suggestions += Suggestion(
                    title = "使用应用私有资源",
                    detail = "把需要的文件随 APK 打包，或下载到 context.filesDir / cacheDir。",
                    command = null
                )
            }

            isApp && isKernelInterface -> {
                ruleId = "kernel_interface"
                summary = "应用访问内核接口被拒绝"
                confidence = 80
                description.append(
                    "应用直接访问 /proc、/sys、/dev 下的内核接口会被 SELinux 阻止。" +
                        "请确认是否可以通过公开 API 或系统服务完成同样的操作。"
                )
                suggestions += Suggestion(
                    title = "改用系统 API",
                    detail = "使用 Android SDK 提供的 API，而不是直接读写内核伪文件系统。",
                    command = null
                )
            }

            else -> {
                description.append(
                    "源域 $sourceType 对目标类型 $targetType 的 ${event.tclass} 缺少 " +
                        "${event.accessText} 权限。"
                )
                if (path.isNotBlank()) description.append("\n目标路径：$path")
                description.append(
                    "\n可能原因：目标文件标签不正确、策略缺少允许规则，或跨域访问本来就不被允许。"
                )
            }
        }

        if (path.startsWith("/")) {
            suggestions += Suggestion(
                title = "查看当前标签",
                detail = "确认目标文件的实际 SELinux 上下文：",
                command = "ls -Zd ${quote(path)}",
                dangerous = false
            )
        }

        suggestions += Suggestion(
            title = "添加文件访问规则",
            detail = "如果确认该访问是必要的，在设备源码中为源域添加最小规则并重新编译：\n${event.policyRule()}",
            command = null
        )

        return Analysis(
            ruleId = ruleId,
            summary = summary,
            description = description.toString(),
            severity = severity,
            confidence = confidence,
            suggestions = suggestions,
            policyRule = event.policyRule()
        )
    }

    private fun genericRule(event: AvcEvent): Analysis {
        return Analysis(
            ruleId = "generic",
            summary = "SELinux 访问被拒绝（${event.tclass}）",
            description = "源域 ${event.scontext.type} 对目标类型 ${event.tcontext.type} 的 " +
                "${event.tclass} 缺少 ${event.accessText} 权限。\n" +
                "这通常意味着设备策略中没有对应的 allow 规则，或者目标对象标签不正确。",
            severity = Severity.WARNING,
            confidence = 65,
            suggestions = listOf(
                Suggestion(
                    title = "确认目标标签",
                    detail = "先确认目标对象标签是否符合预期，再决定是修复标签还是添加 allow 规则。",
                    command = null
                )
            ),
            policyRule = event.policyRule()
        )
    }

    private fun genericSuggestions(event: AvcEvent): List<Suggestion> {
        val list = mutableListOf<Suggestion>()
        list += Suggestion(
            title = "临时切换为 Permissive 诊断",
            detail = "执行 setenforce 0 后重新触发操作，可确认问题是否真的由 SELinux 引起。" +
                "诊断完成后务必执行 setenforce 1 恢复强制模式。",
            command = "setenforce 0",
            dangerous = true
        )
        list += Suggestion(
            title = "使用 Magisk 临时放行（Magisk 设备）",
            detail = "在已 root（Magisk）的设备上可临时注入策略，重启后失效：",
            command = "magiskpolicy --live \"${event.policyRule()}\"",
            dangerous = true
        )
        list += Suggestion(
            title = "永久应用策略规则",
            detail = "推荐在设备源码 system/sepolicy 对应域的 .te 中添加规则后重新编译：" +
                "\n${event.policyRule()}" +
                "\n或把规则写入 Magisk 模块的 sepolicy.rule 并重启。",
            command = null
        )
        return list
    }

    private fun falsePositiveHint(event: AvcEvent): String? {
        val sourceType = event.scontext.type
        return when {
            isAppDomain(sourceType) ->
                "untrusted_app/platform_app 等应用域的很多拒绝属于 Android 正常沙箱限制，" +
                    "只有应用功能确实异常时才需要处理，不要为了消除日志而随意放宽策略。"

            sourceType.contains("su") || sourceType.contains("magisk") ->
                "root/Magisk 域的拒绝通常可通过升级 Magisk 或补充模块 sepolicy.rule 解决。"

            else -> null
        }
    }

    private fun isAppDomain(type: String): Boolean =
        type.startsWith("untrusted_app") || type.startsWith("platform_app") ||
            type.startsWith("priv_app") || type.startsWith("system_app") ||
            type.startsWith("isolated_app") || type.startsWith("ephemeral_app")

    private fun isAppDataLabel(type: String): Boolean =
        type == "app_data_file" || type.endsWith("_app_data_file") || type.endsWith("_data_file")

    private fun quote(value: String): String =
        "'" + value.replace("'", "'\\''") + "'"

    private val capabilityNotes = mapOf(
        "net_admin" to "管理系统网络（防火墙、路由、网卡）",
        "net_raw" to "发送原始网络包",
        "net_bind_service" to "绑定小于 1024 的特权端口",
        "sys_admin" to "系统管理（mount、sethostname 等）",
        "sys_ptrace" to "ptrace 其他进程",
        "sys_module" to "加载/卸载内核模块",
        "sys_boot" to "重启或关闭系统",
        "sys_nice" to "提高调度优先级",
        "sys_resource" to "修改资源限制",
        "sys_time" to "修改系统时间",
        "syslog" to "读取内核日志",
        "dac_override" to "绕过文件读写执行权限检查",
        "dac_read_search" to "绕过目录搜索与文件读权限检查",
        "setuid" to "修改进程 UID",
        "setgid" to "修改进程 GID",
        "setpcap" to "设置进程能力",
        "setfcap" to "设置文件能力",
        "chown" to "修改文件属主",
        "fowner" to "修改文件属主相关属性",
        "kill" to "向任意进程发送信号",
        "mknod" to "创建设备节点",
        "chroot" to "改变根目录",
        "mac_admin" to "修改 SELinux 策略或标签",
        "mac_override" to "绕过强制访问控制",
        "audit_control" to "控制审计规则",
        "audit_write" to "写审计日志",
        "ipc_lock" to "锁定共享内存",
        "wake_alarm" to "设置唤醒闹钟",
        "block_suspend" to "阻止系统挂起",
        "sys_tty_config" to "配置 TTY"
    )
}
