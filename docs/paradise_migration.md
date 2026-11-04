# 内核后端迁移：NI 驱动 → Paradise 驱动

本文记录 engine 内存后端从 NI 驱动（`NI.ko` / `NiDriver`）完整替换为 Paradise 驱动
（`libparadise_api.a` + `paradise_api.h` + 外部 loader）的实现细节、能力映射与语义损失。

CE 线协议（`engine/ceserver/cmd.md`）、GUI、MCP 层**均未改动**，替换只发生在 engine 内部。

## 1. 替换范围

| 项目 | 迁移前 | 迁移后 |
|------|--------|--------|
| 驱动连接 | `NiDriver` 通过 `syscall(__NR_reboot, 0xDEADBEEF, 0x114514, &fd)` 拿 anon_fd，并校验 `NI_CTL_MAGIC` | `paradise_driver` 构造时通过 `syscall(__NR_reboot, 0x7a3b9c4d, 0x2f8e1d6b, &fd)` 拿 anon_fd |
| 传输 | `read(fd, ni_request + payload)` 二进制协议 | `ioctl(fd, 0xc0285709/0xc028570c, ...)`（由 SDK 封装） |
| 授权 | `NI_IOCTL_GET_EXPIRE_TIME` 卡密到期时间 | 无卡密概念，`GetExpireTime` 恒返回 0（永久） |
| 模块加载 | engine 内 `finit_module` 加载 `NI.ko` | 由外部 loader 预置，engine 不再加载内核模块 |
| 内存通道 | `AndroidMemKernel` | `AndroidMemParadise` |
| 硬件断点 | `KernelHwBreakpoint`（per-tid 句柄 + 线程 rescan） | `ParadiseHwBreakpoint`（进程级整表下发） |
| 执行断点 | `UXN`（NI 专有异常断点，命中挂起线程） | `ptebp`（PTE 级执行断点，命中只记录不挂起） |

删除文件：`NiDriver.h/.cpp`、`AndroidKernelDriver.h/.cpp`、`AndroidMemKernel.hpp`、`KernelHwBreakpoint.hpp`。
新增文件：`ParadiseKernelDriver.h/.cpp`、`AndroidMemParadise.hpp`、`ParadiseHwBreakpoint.hpp`、`ParadiseTypes.h`。
SDK 目录：`engine/third_party/paradise/`。

## 2. 能力映射

### 2.1 内存与进程

| 原有能力 | Paradise 实现 | 说明 |
|----------|---------------|------|
| `OpenProcess(pid)` | `open_process` → `initialize(pid)` + `is_process_alive` | handle 就是 pid |
| `ReadMemory` | `paradise_driver::read` | 按页切片，保持「连续前缀」契约 |
| `WriteMemory` | `paradise_driver::write` | 同上 |
| `QueryMaps` | 回退读 `/proc/<pid>/maps` | SDK 不导出 maps 接口 |
| `GetProcessPidList` | `list_processes` 位图 | 位图 64 KiB，覆盖 pid_max |
| `GetProcessCmdline/Comm` | 回退读 `/proc` | 内核接口不提供该信息 |
| `GetSoBaseAddress` | `get_module_base(name)` | 内核层直接取，maps 不可见时仍可用 |

### 2.2 硬件断点

Paradise 的 hwbp 是**整表下发**模型：`hwbp_set(points[], count)` 一次覆盖全部点位，
上限 `PARADISE_HWBP_MAX_POINTS = 16`，每个点位最多 `256` 条记录，记录按触发 PC 聚合。

适配方式：`ParadiseKernelDriver` 维护「逻辑 handle → 点位下标」表，任何增删都
重算整表再下发一次。点位全部以 `scope = ALL_THREADS` 安装，因此不需要原
`KernelHwBreakpoint` 的 per-tid 下断与线程 rescan 线程。

断点类型保持 CE 编码：`1=读 2=写 3=读写 4=执行`。
长度归一化：`3` 字节（x86 遗留）向上取 `4`，其余只接受 `1/2/4/8`。

### 2.3 执行断点（UXN → ptebp）

| UXN 命令 | ptebp 映射 |
|----------|-----------|
| `CMD_KERNEL_UXN_INSTALL` | `ptebp_set` 追加一个执行断点，`slot` = 点位下标（0..15） |
| `CMD_KERNEL_UXN_REMOVE` | 移除对应点位并重下整表 |
| `CMD_KERNEL_UXN_WAIT` | 轮询 `ptebp_get_records`，取 `hit_count > last_seq` 的首条新记录 |
| `CMD_KERNEL_UXN_RESUME` | 空操作（线程从未挂起）；带 `SET_REGS` 时回写记录快照 |
| `CMD_KERNEL_UXN_STATUS` | 由槽位表组合 |
| `CMD_KERNEL_UXN_CLEAR` | `ptebp_remove` |

## 3. 语义损失（必须知道）

1. **执行断点不挂起线程。** NI 的 UXN 命中会暂停命中线程，`resume` 才放行。
   ptebp 只累积记录。为让既有 `wait → resume` 流程与 MCP 工具继续可用，
   `ni_uxn_event.state` 统一上报 `PAUSED`，但 `resume` 实际是空操作。
   目标进程的执行**不会**真的被暂停。

2. **`resume` 的 `set_x0` 不生效。** `ptebp_set_record` 改写的是驱动侧记录快照，
   不是目标线程寄存器。因此「命中后改 X0 再放行」这条链路在 Paradise 上不成立。

3. **无命中时间戳、无 tid。** `paradise_hwbp_record` / `paradise_ptebp_record` 只有
   `hit_count` 与寄存器快照，没有时间戳和线程 ID。`HW_HIT_ITEM.hit_time` 用
   `hit_count` 占位，`ni_uxn_event.tid` 填 pid。

4. **`fault_address` / `esr` 恒为 0。** PTE 记录不含异常 FAR/ESR。

5. **读写短读精度降到页级。** `paradise_driver::read/write` 返回 `bool`，不返回实际
   字节数，所以「连续前缀」的边界只能按页判定。跨页部分成功无法在用户态还原。

6. **断点容量：16 个数据/观察断点 + 16 个执行断点。** 两者是独立的点位池。

7. **多进程无法同时监控。** Paradise 对象只有一个 `pid` 字段，`initialize` 是全局状态。
   在进程 A 与 B 之间切换会重新绑定，A 的断点配置会失效。原有 NI 后端也有单目标限制，
   但句柄模型允许并存，这里退化为严格单目标。

8. **重下整表会重置记录。** 任何断点增删都会重新 `hwbp_set`，历史命中随之作废。

## 4. 构建

```bash
export ANDROID_NDK=$HOME/android-ndk-r27c
cd engine
cmake -S . -B build -G Ninja \
      -DANDROID_NDK="$ANDROID_NDK" \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

产物 `engine/bin/minimem_server`（AArch64）。已实测：NDK r27c + CMake 4.4 + Clang 18 通过。

设备端准备：

```
adb push engine/bin/minimem_server /data/local/tmp/
adb push <paradise loader> /data/local/tmp/
adb shell su -c "sh /data/local/tmp/paradise-*-loader_sfx.sh"
adb shell su -c "chmod +x /data/local/tmp/minimem_server && /data/local/tmp/minimem_server"
```

## 5. 上线前验证清单

- [ ] `CMD_GETMEMTYPE` 返回 3（kernel）
- [ ] `list_processes` / `open_process` / `list_modules` 正常
- [ ] `read_memory` 在可读页返回正确字节，跨越不可读页时 `read < size`
- [ ] `write_memory` 部分写入时 `written < size` 且前 `written` 字节真实生效
- [ ] `set_breakpoint` 4 种类型各下一枚，`read_bp_info` 能看到 `hit_count` 增长
- [ ] 第 17 个断点被拒绝（返回 0），而不是崩溃
- [ ] UXN 安装 / 等待 / 状态 / 移除走通，且确认目标线程**没有**被挂起
- [ ] 断开后重新 `init_driver` 能复用连接（`InitReadWriteDriver` 返回 2）

## 6. 后续可做

- 把 `ptebp_get_coord_samples` 暴露为独立能力（Paradise 独有的浮点坐标采样，最多 2048 条）
- 把 `hide_process` / `hide_path` 接上（驱动自带反检测能力，当前未使用）
- `get_thread_pacga_key` / `bind_thread_pacga_key` 可用于跨线程 PAC 校验场景
- 触摸注入（`touch_init/down/move/up/event`）与 `gyro_update` 尚未接入