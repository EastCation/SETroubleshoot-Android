<!-- 仓库：https://github.com/EastCation/SETroubleshoot-Android -->
# SETroubleshoot for Android

[![Build](https://github.com/EastCation/SETroubleshoot-Android/actions/workflows/build.yml/badge.svg)](https://github.com/EastCation/SETroubleshoot-Android/actions/workflows/build.yml)

面向 **已 root Android 设备** 的 SELinux AVC 排障工具。它可以读取 `dmesg`、`logcat`、`audit.log`，解析并聚合 SELinux 拒绝记录，解释拒绝原因，给出修复建议，并生成 `allow` 策略规则。

> 设计参考 Fedora [setroubleshoot](https://github.com/fedora-selinux/setroubleshoot) 的 AVC 解析、audit 事件合并、告警签名聚合与报告格式；解析器和分析规则针对 Android 场景重新实现。

## 功能

- **SELinux 状态**：root 状态、Enforcing / Permissive / Disabled、当前上下文、策略版本、设备与 Android 版本
- **多种来源**：
  - `dmesg`（内核 AVC）
  - `logcat`（全部缓冲区）
  - `/data/misc/audit/audit.log`（存在时）
  - 手动粘贴日志
  - 一键扫描全部来源
- **AVC 解析**
  - 支持内核 dmesg 与 audit 文本格式
  - 支持十六进制路径/文件名解码
  - 合并同一 audit 事件的 `SYSCALL` / `PATH` / `CWD` / `AVC_PATH` 记录
  - 相对路径结合 `cwd` 还原为绝对路径
- **告警聚合**：按「来源域 + 目标类型 + 目标类 + 权限」合并同类告警，显示次数与最近一次详情
- **Android 专用分析规则**
  - Permissive / 未真正拒绝
  - root / Magisk / su
  - Binder、service_manager、property_service
  - capability、网络端口、unix socket
  - process / ptrace、filesystem
  - 文件标签、应用沙箱、共享存储、W^X 执行限制
- **修复建议**
  - `restorecon -Rv`、`ls -Z`、`getprop -Z`
  - `setenforce 0/1`（临时诊断，高风险）
  - `magiskpolicy --live`（临时生效，高风险）
  - 写入 Magisk 模块 `sepolicy.rule`
  - 生成最小 `allow` 规则
- **报告导出**：复制/分享单条告警完整报告、汇总报告、全部策略规则
- **安全交互**：高风险命令需要二次确认；执行前可先复制命令自行检查

## 环境要求

| 项目 | 要求 |
| --- | --- |
| Android | 10+（API 29 及以上） |
| Root | Magisk / KernelSU / SuperSU 等，需授予本应用 `su` 权限 |
| SELinux | 通常需要 `Enforcing` 才会产生拒绝记录 |
| 构建 | JDK 21、Android Studio（或命令行 Gradle）、SDK Platform 36.1 |
| 工程 | Gradle 9.3.1、AGP 9.1.1、Kotlin 2.2.10、Jetpack Compose |

## 构建

```bash
git clone https://github.com/EastCation/SETroubleshoot-Android.git
cd SETroubleshoot

# Linux / macOS
./gradlew :app:assembleDebug

# Windows
gradlew.bat :app:assembleDebug
```

生成的 APK：

```text
app/build/outputs/apk/debug/app-debug.apk
```

运行单元测试与静态检查：

```bash
./gradlew :app:testDebugUnitTest :app:lintDebug
```

> 如果 SDK 缺少 `android-36.1`，请在 Android Studio 的 SDK Manager 中安装对应 Platform，或执行：
>
> ```bash
> sdkmanager "platforms;android-36.1" "build-tools;36.1.0"
> ```

## 使用

1. 安装 APK，首次启动时在 root 管理器中授予 `su` 权限。
2. 点击「刷新」读取 SELinux 状态。
3. 选择扫描来源：`dmesg`、`logcat`、`audit.log` 或「扫描全部来源」。
4. 在告警列表中使用「全部 / 提示 / 警告 / 危险」筛选，点击告警查看详情。
5. 查看分析、上下文、原始审计消息，以及修复建议。
6. 需要生成策略时：
   - 复制单条 `allow` 规则或「复制策略」获取全部去重规则；
   - 推荐加入设备源码 `system/sepolicy` 对应域的 `.te`，重新编译策略；
   - 或写入 Magisk 模块的 `sepolicy.rule` 后重启。
7. 执行 `restorecon` / `setenforce` / `magiskpolicy` 等命令前请先确认影响；高风险命令会二次确认。

### 示例

`dmesg` 或 `logcat` 中的一条典型 AVC：

```text
avc: denied { read } for pid=12345 comm="untrusted_app" name="config.xml" \
dev="dm-0" ino=123456 scontext=u:r:untrusted_app:s0:c512,c768 \
tcontext=u:object_r:system_file:s0 tclass=file permissive=0
```

工具会解析为：

- 源：`untrusted_app` / `untrusted_app`
- 目标：`system_file` / `file`
- 权限：`read`
- 分析：普通应用访问系统分区属于 Android 沙箱限制
- 生成的规则：

```text
allow untrusted_app system_file:file { read };
```

## 工作原理

```text
app/src/main/java/cn/moerain/setroubleshoot/
├── AppController.kt              # 状态与后台任务调度
├── data/
│   ├── Models.kt                 # AVC / 告警 / 分析 / SELinux 状态模型
│   ├── AvcParser.kt              # dmesg / audit 解析与事件合并
│   ├── AvcAnalyzer.kt            # Android 场景分析规则
│   └── ReportFormatter.kt        # 文本报告生成
├── system/
│   ├── RootShell.kt              # su / sh 命令执行（超时与兼容处理）
│   ├── SelinuxCollector.kt       # SELinux 状态采集
│   └── DenialCollector.kt        # dmesg / logcat / audit.log 采集
└── ui/
    ├── AppRoot.kt                # 页面切换
    ├── MainScreen.kt             # 状态、扫描、告警列表
    ├── AlertDetailScreen.kt      # 告警详情与修复建议
    ├── PasteLogScreen.kt         # 粘贴日志分析
    └── UiHelpers.kt              # 颜色、徽章、示例日志
```

关键行为：

- **状态读取**：普通应用域通常被禁止读取 `getenforce` 与 `/sys/fs/selinux/enforce`。
  - 有 root 时通过 `su` 读取，能正确显示 `Enforcing` / `Permissive`。
  - 无 root 且无法读取时显示 `状态未知`（而不是误报 `Permissive`）。
  - 应用自身上下文直接读取 `/proc/self/attr/current`，不会显示成 `u:r:su:s0`。
- **采集**：`dmesg` / `logcat` / `audit.log` 的读取需要 root。
- **分析**：`granted` 记录默认过滤；`permissive=1` 或确认系统处于 Permissive 时按“未真正拒绝”处理。
- **策略生成**：只生成最小 `allow` 规则，不会自动修改系统策略。永久生效需自行编译设备策略或使用 Magisk 模块。

## GitHub Actions

工作流文件：`.github/workflows/build.yml`

触发条件：

- 任意分支 push（实时构建最新代码）
- Pull Request
- 推送 `v*` 标签
- 手动 `workflow_dispatch`

每次运行会：

1. 安装 JDK 21 与 Android SDK（Platform 36.1）
2. 执行单元测试与 Lint
3. 构建 Debug APK
4. 上传构建产物 `SETroubleshoot-debug`
5. 推送 `v*` 标签时创建 GitHub Release，附带 APK 与 SHA-256 校验文件
6. push 到 `main` / `master` 时更新滚动预发布版本 `latest`，方便直接下载最新构建

下载方式：

- 任意一次 Actions 运行 → **Artifacts** → `SETroubleshoot-debug`
- 或打开 **Releases** → `Latest build` / 标签版本

> CI 产出的是 **debug 签名** APK，适合测试与侧载。正式分发请在本地配置自己的签名密钥，或在 Workflow 中增加 keystore secrets 并构建 `release`。

## 常见问题

**Q：为什么显示“状态未知”？**

无 root，或 root 未授权。Android 的 `untrusted_app` / `runas_app` 域禁止读取 SELinux enforce 状态，必须在 root 管理器中给应用授权后点击刷新。

**Q：扫描不到 AVC？**

- `dmesg` / `logcat` 需要 root；
- SELinux 需要处于 `Enforcing` 并实际产生过拒绝；
- 可尝试 `audit.log` 或直接粘贴日志；
- 部分设备会限制内核日志，建议使用 Magisk / KernelSU 环境。

**Q：`adb shell su` 提示 not found，但应用可以用 root？**

部分 root 方案只向被授权的应用提供 `su`，不给 `adb shell`。以应用内授权结果为准。

**Q：可以直接执行 `allow` 规则吗？**

可以生成规则文本，但不会自动写入系统策略。永久生效需要编译设备 sepolicy，或使用 Magisk 模块的 `sepolicy.rule`。请遵循最小权限原则，不要盲目放行整个域。

## 安全提示

- `setenforce 0`、`magiskpolicy --live` 会临时削弱或修改 SELinux 策略；
- `restorecon -Rv` 会重新标记文件，执行前请确认路径；
- 自动生成的 `allow` 规则仅作为参考，合并进策略前应人工审查；
- 本工具不会上传任何日志或设备信息。

## 许可证与致谢

- 本项目代码与文档：**GNU General Public License v3.0**
- 图标：来自 [Papirus Icon Theme](https://github.com/PapirusDevelopmentTeam/papirus-icon-theme) 的 `selinux.svg`（GPL-3.0）
- 设计参考：[setroubleshoot](https://github.com/fedora-selinux/setroubleshoot)（GPL-2.0），本仓库未直接包含其源代码
- 依赖：AndroidX / Jetpack Compose（Apache-2.0）、Kotlin（Apache-2.0）

完整许可证见 [LICENSE](LICENSE)。
