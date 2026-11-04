#ifndef PARADISE_API_H
#define PARADISE_API_H

#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>

#define PARADISE_GYRO_MASK_GYRO (1u << 0)
#define PARADISE_GYRO_MASK_UNCAL (1u << 1)
#define PARADISE_GYRO_MASK_ALL (PARADISE_GYRO_MASK_GYRO | PARADISE_GYRO_MASK_UNCAL)


#define PARADISE_BP_OP_NONE    0x0
#define PARADISE_BP_OP_READ    0x1
#define PARADISE_BP_OP_WRITE   0x2
#define PARADISE_HWBP_MAX_POINTS 16
#define PARADISE_HWBP_MAX_RECORDS 256

enum paradise_hwbp_type {
    PARADISE_HWBP_EMPTY = 0,
    PARADISE_HWBP_READ = 1,
    PARADISE_HWBP_WRITE = 2,
    PARADISE_HWBP_READ_WRITE = 3,
    PARADISE_HWBP_EXECUTE = 4,
};

enum paradise_hwbp_scope {
    PARADISE_HWBP_MAIN_THREAD = 0,
    PARADISE_HWBP_OTHER_THREADS = 1,
    PARADISE_HWBP_ALL_THREADS = 2,
};

enum paradise_hwbp_register {
    PARADISE_REG_PC = 0,
    PARADISE_REG_HIT_COUNT,
    PARADISE_REG_LR,
    PARADISE_REG_SP,
    PARADISE_REG_ORIG_X0,
    PARADISE_REG_SYSCALLNO,
    PARADISE_REG_PSTATE,
    PARADISE_REG_X0,
    PARADISE_REG_X1,
    PARADISE_REG_X2,
    PARADISE_REG_X3,
    PARADISE_REG_X4,
    PARADISE_REG_X5,
    PARADISE_REG_X6,
    PARADISE_REG_X7,
    PARADISE_REG_X8,
    PARADISE_REG_X9,
    PARADISE_REG_X10,
    PARADISE_REG_X11,
    PARADISE_REG_X12,
    PARADISE_REG_X13,
    PARADISE_REG_X14,
    PARADISE_REG_X15,
    PARADISE_REG_X16,
    PARADISE_REG_X17,
    PARADISE_REG_X18,
    PARADISE_REG_X19,
    PARADISE_REG_X20,
    PARADISE_REG_X21,
    PARADISE_REG_X22,
    PARADISE_REG_X23,
    PARADISE_REG_X24,
    PARADISE_REG_X25,
    PARADISE_REG_X26,
    PARADISE_REG_X27,
    PARADISE_REG_X28,
    PARADISE_REG_X29,
    PARADISE_REG_FPSR,
    PARADISE_REG_FPCR,
    PARADISE_REG_Q0,
    PARADISE_REG_Q1,
    PARADISE_REG_Q2,
    PARADISE_REG_Q3,
    PARADISE_REG_Q4,
    PARADISE_REG_Q5,
    PARADISE_REG_Q6,
    PARADISE_REG_Q7,
    PARADISE_REG_Q8,
    PARADISE_REG_Q9,
    PARADISE_REG_Q10,
    PARADISE_REG_Q11,
    PARADISE_REG_Q12,
    PARADISE_REG_Q13,
    PARADISE_REG_Q14,
    PARADISE_REG_Q15,
    PARADISE_REG_Q16,
    PARADISE_REG_Q17,
    PARADISE_REG_Q18,
    PARADISE_REG_Q19,
    PARADISE_REG_Q20,
    PARADISE_REG_Q21,
    PARADISE_REG_Q22,
    PARADISE_REG_Q23,
    PARADISE_REG_Q24,
    PARADISE_REG_Q25,
    PARADISE_REG_Q26,
    PARADISE_REG_Q27,
    PARADISE_REG_Q28,
    PARADISE_REG_Q29,
    PARADISE_REG_Q30,
    PARADISE_REG_Q31,
    PARADISE_REG_COUNT,
};

#define PARADISE_BP_SET_MASK(record, reg, op)                       \
    do {                                                            \
        int byte_index = (reg) >> 2;                                \
        int bit_offset = ((reg) & 0x3) << 1;                        \
        (record)->mask[byte_index] &= ~(0x3 << bit_offset);         \
        (record)->mask[byte_index] |= ((op) & 0x3) << bit_offset;   \
    } while (0)

#define PARADISE_BP_GET_MASK(record, reg) \
    (((record)->mask[(reg) >> 2] >> (((reg) & 0x3) << 1)) & 0x3)

struct paradise_hwbp_record {
    uint8_t mask[18];
    uint64_t hit_count;
    uint64_t pc;
    uint64_t lr;
    uint64_t sp;
    uint64_t orig_x0;
    uint64_t syscallno;
    uint64_t pstate;
    uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9;
    uint64_t x10, x11, x12, x13, x14, x15, x16, x17, x18, x19;
    uint64_t x20, x21, x22, x23, x24, x25, x26, x27, x28, x29;
    uint32_t fpsr;
    uint32_t fpcr;
    __uint128_t q0, q1, q2, q3, q4, q5, q6, q7, q8, q9;
    __uint128_t q10, q11, q12, q13, q14, q15, q16, q17, q18, q19;
    __uint128_t q20, q21, q22, q23, q24, q25, q26, q27, q28, q29;
    __uint128_t q30, q31;
};

struct paradise_hwbp_point_config {
    uint64_t address;
    uint32_t type;
    uint32_t length;
    uint32_t scope;
    uint32_t reserved;
};

struct paradise_hwbp_config {
    int32_t tgid;
    uint32_t point_count;
    uint64_t num_brps;
    uint64_t num_wrps;
    paradise_hwbp_point_config points[PARADISE_HWBP_MAX_POINTS];
};

static_assert(sizeof(paradise_hwbp_record) == 848,
              "paradise_hwbp_record ABI mismatch");
static_assert(sizeof(paradise_hwbp_config) == 408,
              "paradise_hwbp_config ABI mismatch");

/* PTE records preserve vndriver's signed 32-bit syscall number. */
#define PARADISE_PTEBP_MAX_POINTS 16
#define PARADISE_PTEBP_MAX_RECORDS 0x100
#define PARADISE_PTEBP_MAX_COORD_SAMPLES 2048
#define PARADISE_PTEBP_POINT_COORD_X0_Q0_Q1_Q2             (1U << 0)
#define PARADISE_PTEBP_POINT_COORD_X20_XY_X8_Z_X9          (1U << 1)
#define PARADISE_PTEBP_POINT_COORD_X19_XY_X9_Z_X8          (1U << 2)
#define PARADISE_PTEBP_POINT_COORD_X19_Q0_Q1_Q2            (1U << 3)
#define PARADISE_PTEBP_POINT_COORD_X22_XY_X8_Z_X10         (1U << 4)
#define PARADISE_PTEBP_POINT_COORD_MASK                     \
    (PARADISE_PTEBP_POINT_COORD_X0_Q0_Q1_Q2 |              \
     PARADISE_PTEBP_POINT_COORD_X20_XY_X8_Z_X9 |           \
     PARADISE_PTEBP_POINT_COORD_X19_XY_X9_Z_X8 |           \
     PARADISE_PTEBP_POINT_COORD_X19_Q0_Q1_Q2 |             \
     PARADISE_PTEBP_POINT_COORD_X22_XY_X8_Z_X10)

struct paradise_ptebp_record {
    uint8_t mask[18];
    uint64_t hit_count;
    uint64_t pc;
    uint64_t lr;
    uint64_t sp;
    uint64_t orig_x0;
    int32_t syscallno;
    uint64_t pstate;
    uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9;
    uint64_t x10, x11, x12, x13, x14, x15, x16, x17, x18, x19;
    uint64_t x20, x21, x22, x23, x24, x25, x26, x27, x28, x29;
    uint32_t fpsr;
    uint32_t fpcr;
    __uint128_t q0, q1, q2, q3, q4, q5, q6, q7, q8, q9;
    __uint128_t q10, q11, q12, q13, q14, q15, q16, q17, q18, q19;
    __uint128_t q20, q21, q22, q23, q24, q25, q26, q27, q28, q29;
    __uint128_t q30, q31;
};

struct paradise_ptebp_point_config {
    uint64_t address;
    uint32_t type;
    uint32_t length;
    uint32_t scope;
    uint32_t reserved;
};

struct paradise_ptebp_config {
    int32_t tgid;
    uint32_t point_count;
    uint64_t num_brps;
    uint64_t num_wrps;
    paradise_ptebp_point_config points[PARADISE_PTEBP_MAX_POINTS];
};

struct paradise_ptebp_coord_sample {
    uint64_t sequence;
    uint64_t hit_count;
    uint64_t pc;
    uint64_t component;
    uint32_t x_bits;
    uint32_t y_bits;
    uint32_t z_bits;
    uint32_t reserved;
};

static_assert(sizeof(paradise_ptebp_record) == 848,
              "paradise_ptebp_record ABI mismatch");
static_assert(sizeof(paradise_ptebp_config) == 408,
              "paradise_ptebp_config ABI mismatch");
static_assert(sizeof(paradise_ptebp_coord_sample) == 48,
              "paradise_ptebp_coord_sample ABI mismatch");

class paradise_driver {
private:
    pid_t pid;
    int fd;
    uint32_t touch_x_proportion = 0;
    uint32_t touch_y_proportion = 0;

    int install_driver_fd();
    void ensure_connected();

public:
    // 构造时连接 Paradise 驱动
    paradise_driver();
    
    // 构析方法
    ~paradise_driver();

    // 初始化目标 pid，读写前务必调用一次
    void initialize(pid_t target_pid);
    
    // 获取进程pid，传入进程名称，从内核层安全获取pid
    pid_t get_pid(const char *name);
    
    // 获取模块基址，传入模块名，从内核层安全获取模块基址
    uintptr_t get_module_base(const char *name);
    
    // 更新陀螺仪数据
    bool gyro_update(float x, float y, uint32_t type_mask = PARADISE_GYRO_MASK_ALL, bool enable = true);
    
    // 检查进程是否存活 (alive_out: 1为存活，0为未存活)
    bool is_process_alive(pid_t check_pid, int *alive_out);
    
    // 隐藏或取消隐藏指定进程
    bool hide_process(pid_t target_pid, bool hide);
    
    // 隐藏或取消隐藏指定路径
    bool hide_path(const char *path, bool hide);
    
    // 获取进程列表位图
    bool list_processes(uint8_t *bitmap, size_t bitmap_size, size_t *process_count_out);

    // 获取进程主线程的 TPIDR_EL0。
    uintptr_t get_main_thread_elf0(pid_t target_pid);

    // 获取指定线程的 TPIDR_EL0。
    uintptr_t get_thread_tpidr_el0(pid_t tid);

    // 获取指定线程的 PACGA 密钥及算法编号。
    bool get_thread_pacga_key(pid_t tid, uint64_t *lo, uint64_t *hi,
                              uint32_t *algo = nullptr);

    // 获取指定线程的 PACIA 密钥及算法编号。
    bool get_thread_pacia_key(pid_t tid, uint64_t *lo, uint64_t *hi,
                              uint32_t *algo = nullptr);

    // 将 tid 的 PACGA 密钥绑定为 target_tid 的 PACGA 密钥。
    bool bind_thread_pacga_key(pid_t tid, pid_t target_tid);
    
    // 读取，传入地址、接收指针、类型大小
    bool read(uintptr_t addr, void *buffer, size_t size);
    
    // 写入，传入地址、数据指针、类型大小
    bool write(uintptr_t addr, void *buffer, size_t size);

    // 输入屏幕宽高，内部按短边 X、长边 Y 保存旧接口的整数缩放比例。
    bool touch_init(int abs_screen_x, int abs_screen_y);

    // x/y 沿用原有屏幕坐标，内部转换为 ABS_MT 坐标；slot 为 0..9。
    // 重复 down 不移动；移动使用 touch_move。
    bool touch_down(int slot, int x, int y);
    bool touch_move(int slot, int x, int y);

    // 抬起指定 slot
    bool touch_up(int slot);

    // 原始 ABS_MT 坐标接口，不做缩放：command=2/3/4，mask 低十位；零掩码默认槽位 9。
    bool touch_event(uint32_t command, uint32_t x, uint32_t y, uint16_t mask);

    // 设置最多 16 个 ARM64 执行断点/访问观察点。
    bool hwbp_set(const paradise_hwbp_point_config *points, size_t point_count);

    // 删除当前硬件断点/观察点并清理所有 CPU 调试寄存器。
    bool hwbp_remove();

    // 获取当前配置以及 CPU 支持的 BRP/WRP 数量。
    bool hwbp_get_config(paradise_hwbp_config *config_out);

    // 分段读取指定点位按触发 PC 聚合的现场记录。
    bool hwbp_get_records(uint32_t point_index, uint32_t start_index,
                          paradise_hwbp_record *records, uint32_t capacity,
                          uint32_t *count_out);

    // 写回一条记录及其 2-bit 寄存器操作掩码。
    bool hwbp_set_record(uint32_t point_index, uint32_t record_index,
                         const paradise_hwbp_record *record);

    // 清空一个点位的记录；point_index=-1 清空全部点位。
    bool hwbp_clear_records(int32_t point_index = -1);

    // PTE 执行断点：最多 16 个，type=EXECUTE、length=4。
    bool ptebp_set(const paradise_ptebp_point_config *points, size_t point_count);
    bool ptebp_remove();

    // num_brps/num_wrps 为零；监控自动撤销后返回空配置，记录仍可读取。
    bool ptebp_get_config(paradise_ptebp_config *config_out);
    bool ptebp_get_records(uint32_t point_index, uint32_t start_index,
                           paradise_ptebp_record *records, uint32_t capacity,
                           uint32_t *count_out);
    bool ptebp_set_record(uint32_t point_index, uint32_t record_index,
                          const paradise_ptebp_record *record);
    bool ptebp_clear_records(int32_t point_index = -1);
    bool ptebp_get_coord_samples(uint64_t after_sequence,
                                 paradise_ptebp_coord_sample *samples,
                                 uint32_t capacity, uint32_t *count_out,
                                 uint64_t *newest_sequence_out);

    // 模板方法，传入地址，返回地址上的值
    template <typename T>
    T read(uintptr_t addr)
    {
        T res{};
        if (this->read(addr, &res, sizeof(T)))
            return res;
        return {};
    }

    // 模板方法，传入地址，修改后的值
    template <typename T>
    bool write(uintptr_t addr, T value)
    {
        return this->write(addr, &value, sizeof(T));
    }
};

#endif
