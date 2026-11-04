#pragma once
// ============================================================================
// ParadiseTypes.h — CE 线协议依赖的结构定义
// ----------------------------------------------------------------------------
// 这些结构原先把放在 NiDriver.h 中。改用 Paradise 驱动后，Paradise 的
// paradise_hwbp_record / paradise_ptebp_record 与本文件结构不同，无法直接复用，
// 因此这里只保留「CE socket 协议层」需要的数据结构（UXN 事件、HWBP 任务查询），
// 由 ParadiseKernelDriver 在内部完成 paradise_* <-> ni_* 的转换。
//
// 保留 ni_uxn_* 命名是为了让 engine/ceserver/cmd.md 描述的线格式保持不变，
// 客户端（GUI / MCP）无需任何改动。
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <vector>

/* ── HWBP 常量 ──────────────────────────────────────────────────── */

constexpr int NI_HWBP_MAX_EVENTS_PER_READ = 256;
constexpr uint32_t NI_HWBP_MAX_QUERY_ENTRIES = 64;

constexpr uint32_t NI_HW_BREAKPOINT_X  = 4;
constexpr uint32_t NI_HW_BREAKPOINT_R  = 1;
constexpr uint32_t NI_HW_BREAKPOINT_W  = 2;
constexpr uint32_t NI_HW_BREAKPOINT_RW = 3;

constexpr uint32_t NI_HW_BREAKPOINT_LEN_1 = 1;
constexpr uint32_t NI_HW_BREAKPOINT_LEN_2 = 2;
constexpr uint32_t NI_HW_BREAKPOINT_LEN_3 = 3;
constexpr uint32_t NI_HW_BREAKPOINT_LEN_4 = 4;
constexpr uint32_t NI_HW_BREAKPOINT_LEN_8 = 8;

/* ── HWBP 任务查询（CE 协议 CMD_KERNEL_QUERYHWBPTHREADS 的线结构） ── */

struct ni_hwbp_task_entry {
	uint64_t event_id;
	uint64_t module_handle;
	uint64_t addr;
	int32_t  tid;
	int32_t  oncpu;
	uint32_t type;
	uint32_t len;
	uint32_t state;
	uint32_t source;
	uint32_t flags;
	uint32_t reserved;
};

struct ni_hwbp_task_query {
	int32_t  tid;
	uint32_t flags;
	uint64_t entries;          // 用户态回填的缓冲区地址，线协议中不使用
	uint32_t capacity;
	uint32_t count;
	uint32_t total_count;
	uint32_t brp_count;
	uint32_t wrp_count;
	uint32_t enabled_count;
	uint32_t active_count;
	uint32_t perf_count;
	uint32_t ptrace_count;
	uint32_t module_count;
	uint32_t reserved;
};

struct ni_hwbp_task_cleanup {
	int32_t  pid;
	uint32_t flags;
	uint32_t cleaned_count;
	uint32_t reserved;
};

static_assert(sizeof(ni_hwbp_task_entry) == 56,
	      "ni_hwbp_task_entry ABI size mismatch");
static_assert(sizeof(ni_hwbp_task_query) == 64,
	      "ni_hwbp_task_query ABI size mismatch");
static_assert(sizeof(ni_hwbp_task_cleanup) == 16,
	      "ni_hwbp_task_cleanup ABI size mismatch");

struct ni_hwbp_task_snapshot {
	ni_hwbp_task_query summary;
	std::vector<ni_hwbp_task_entry> entries;
};

/* ── UXN 执行异常断点（CE 协议 CMD_KERNEL_UXN_* 的线结构） ─────────
 * Paradise 驱动没有「命中即挂起线程再 resume」的 UXN 能力，此处由
 * paradise ptebp（PTE 执行断点）承载，语义映射见 ParadiseKernelDriver.cpp。
 * ────────────────────────────────────────────────────────────────── */

constexpr uint32_t NI_UXN_MAX_SLOTS = 16;
constexpr uint32_t NI_UXN_REG_COUNT = 31;
constexpr uint32_t NI_UXN_FP_REG_COUNT = 32;
constexpr uint32_t NI_UXN_WAIT_ANY_SLOT = UINT32_MAX;
constexpr size_t NI_UXN_REGS_SIZE = 272;
constexpr size_t NI_UXN_FPSIMD_REGS_SIZE = 528;
constexpr size_t NI_UXN_EVENT_SIZE = 880;
constexpr size_t NI_UXN_WAIT_SIZE = 896;
constexpr size_t NI_UXN_RESUME_SIZE = 280;

enum NiUxnState : uint32_t {
	NI_UXN_STATE_EMPTY = 0,
	NI_UXN_STATE_ARMED,
	NI_UXN_STATE_PAUSED,
	NI_UXN_STATE_STEPPING,
};

enum NiUxnResumeFlags : uint32_t {
	NI_UXN_RESUME_F_SET_REGS = 1u << 0,
};

enum NiUxnFpsimdFlags : uint32_t {
	NI_UXN_REGS_F_FPSIMD_VALID = 1u << 0,
};

struct ni_uxn_regs {
	uint64_t regs[NI_UXN_REG_COUNT];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
};

struct ni_uxn_fpsimd_regs {
	__uint128_t fp_regs[NI_UXN_FP_REG_COUNT];
	uint32_t fpsr;
	uint32_t fpcr;
	uint32_t flags;
	uint32_t reserved;
};

struct ni_uxn_install {
	uint32_t pid;
	uint32_t flags;
	uint64_t addr;
	uint32_t slot;
	uint32_t reserved;
};

struct ni_uxn_remove {
	uint32_t pid;
	uint32_t reserved;
	uint64_t addr;
};

struct ni_uxn_event {
	uint32_t slot;
	uint32_t pid;
	uint32_t tid;
	uint32_t state;
	uint64_t seq;
	uint64_t addr;
	uint64_t page;
	uint64_t fault_address;
	uint64_t esr;
	uint64_t hits;
	uint64_t false_hits;
	ni_uxn_regs regs;
	ni_uxn_fpsimd_regs fpsimd;
};

struct ni_uxn_wait {
	uint32_t slot;
	uint32_t timeout_ms;
	uint64_t last_seq;
	ni_uxn_event event;
};

struct ni_uxn_resume {
	uint32_t slot;
	uint32_t flags;
	ni_uxn_regs regs;
};

struct ni_uxn_status {
	uint32_t slot;
	uint32_t used;
	uint32_t pid;
	uint32_t tid;
	uint32_t state;
	int32_t last_error;
	uint64_t addr;
	uint64_t page;
	uint64_t hits;
	uint64_t false_hits;
	uint64_t step_hits;
	uint64_t resumes;
	uint64_t seq;
};

static_assert(sizeof(ni_uxn_regs) == NI_UXN_REGS_SIZE,
	      "ni_uxn_regs ABI size mismatch");
static_assert(sizeof(ni_uxn_fpsimd_regs) == NI_UXN_FPSIMD_REGS_SIZE,
	      "ni_uxn_fpsimd_regs ABI size mismatch");
static_assert(sizeof(ni_uxn_install) == 24, "ni_uxn_install ABI size mismatch");
static_assert(sizeof(ni_uxn_event) == NI_UXN_EVENT_SIZE,
	      "ni_uxn_event ABI size mismatch");
static_assert(offsetof(ni_uxn_event, fault_address) == 40,
	      "ni_uxn_event FAR offset mismatch");
static_assert(sizeof(ni_uxn_wait) == NI_UXN_WAIT_SIZE,
	      "ni_uxn_wait ABI size mismatch");
static_assert(sizeof(ni_uxn_resume) == NI_UXN_RESUME_SIZE,
	      "ni_uxn_resume ABI size mismatch");
static_assert(sizeof(ni_uxn_status) == 80, "ni_uxn_status ABI size mismatch");
