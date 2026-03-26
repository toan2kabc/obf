#ifndef QUOCTOANDEV_H
#define QUOCTOANDEV_H
/* QUOCTOANDEV - Encryption Library */
// Remake by @quoctoansieudz
// Pls don't copy without crediting, thanks :)

#include <cstddef>
#include <cstdint>
#include <type_traits>

// ═══════════════════════════════════════════════════════════════════════
//  CONFIG — on/off features
// ═══════════════════════════════════════════════════════════════════════
/*
#define QTD_CONST_ENCRYPTION          1   // Mã hoá string/constant
#define QTD_CONST_ENCRYPT_THREADLOCAL 0   // 1 = mỗi thread giải riêng
#define QTD_CFLOW_BRANCHING           1   // Bọc if/for/while/switch/return
#define QTD_CFLOW_CONST_DECRYPTION    1   // Nhánh giả trong vòng lặp giải
#define QTD_INDIRECT_BRANCHING        1   // Phá linear-sweep disassembler
#define QTD_MBA_EXPRESSIONS           1   // Mixed Boolean Arithmetic
#define QTD_ANTI_DEBUG                0   // Phát hiện debugger lúc runtime
#define QTD_FAKE_SIGNATURES           0   // Fake PE sections (chỉ Windows)
#define QTD_INLINE_STD                1   // Inline strcpy/strlen/... helpers
#define QTD_KERNEL_MODE               0   // 1 = kernel driver mode
*/

#define QTD_CONST_ENCRYPTION          1   // Mã hoá string/constant
#define QTD_CONST_ENCRYPT_THREADLOCAL 1   // 1 = mỗi thread giải riêng
#define QTD_CFLOW_BRANCHING           1   // Bọc if/for/while/switch/return
#define QTD_CFLOW_CONST_DECRYPTION    1   // Nhánh giả trong vòng lặp giải
#define QTD_INDIRECT_BRANCHING        1   // Phá linear-sweep disassembler
#define QTD_MBA_EXPRESSIONS           1   // Mixed Boolean Arithmetic
#define QTD_ANTI_DEBUG                0   // Phát hiện debugger lúc runtime
#define QTD_FAKE_SIGNATURES           0   // Fake PE sections (chỉ Windows)
#define QTD_INLINE_STD                1   // Inline strcpy/strlen/... helpers
#define QTD_KERNEL_MODE               0   // 1 = kernel driver mode
// ── Compiler detection ───────────────────────────────────────────────
#if defined(_MSC_VER) && !defined(__clang__)
#   define _QTD_MSVC
#   include <intrin.h>   // __readgsqword, __readfsdword, __debugbreak
#   include <malloc.h>   // _alloca (dùng cho _QTD_BREAK_FRAME)
#elif defined(__GNUC__) || defined(__clang__)
#   define _QTD_GNUC
#endif

// ── Architecture detection ───────────────────────────────────────────
// [FIX] Thêm _M_ARM64 cho MSVC ARM64, _M_IX86 cho MSVC x86
#if   defined(__x86_64__)  || defined(_M_X64)
#   define _QTD_ARCH_X64
#elif defined(__i386__)    || defined(_M_IX86) || defined(i386)
#   define _QTD_ARCH_X86
#elif defined(__aarch64__) || defined(_M_ARM64)   // ← MSVC ARM64
#   define _QTD_ARCH_ARM64
#endif

// ── OS detection ─────────────────────────────────────────────────────
#if defined(_WIN64) || defined(_WIN32)
#   define _QTD_WINDOWS
#elif defined(__linux__) || defined(__ANDROID__)
#   define _QTD_LINUX
#elif defined(__APPLE__)
#   define _QTD_APPLE
#endif

// ── Compiler attributes ──────────────────────────────────────────────
#ifdef _QTD_MSVC
#   define QTD_INLINE    __forceinline
#   define QTD_NOINLINE  __declspec(noinline)
#   define QTD_SECTION(x) __declspec(allocate(x))
#else
#   define QTD_INLINE    __attribute__((always_inline)) inline
#   define QTD_NOINLINE  __attribute__((noinline))
#   define QTD_SECTION(x) __attribute__((section(x)))
#endif

// ── Fake PE signatures (Windows only) ───────────────────────────────
#if QTD_FAKE_SIGNATURES && defined(_QTD_WINDOWS) && !QTD_KERNEL_MODE
#   include <windows.h>
#   ifdef _QTD_MSVC
#       pragma section(".arch")
#       pragma section(".srdata")
#       pragma section(".xpdata")
#       pragma section(".xdata")
#       pragma section(".xtls")
#       pragma section(".themida")
#       pragma section(".vmp0")
#       pragma section(".vmp1")
#       pragma section(".vmp2")
#       pragma section(".enigma1")
#       pragma section(".enigma2")
#       pragma section(".dsstext")
#   endif
#   define _QTD_FAKE_SIG(name, sec, sig) \
        QTD_SECTION(sec) volatile static const char* name = (const char*)(sig);
    _QTD_FAKE_SIG(_qtd_vmp0,  ".vmp0",    0)
    _QTD_FAKE_SIG(_qtd_vmp1,  ".vmp1",    0)
    _QTD_FAKE_SIG(_qtd_vmp2,  ".vmp2",    0)
    _QTD_FAKE_SIG(_qtd_enig1, ".enigma1", 0)
    _QTD_FAKE_SIG(_qtd_enig2, ".enigma2", 0)
    _QTD_FAKE_SIG(_qtd_thm,   ".themida", 0)
    _QTD_FAKE_SIG(_qtd_dnv1,  ".arch",    0)
    _QTD_FAKE_SIG(_qtd_dnv2,  ".srdata",  0)
    _QTD_FAKE_SIG(_qtd_dnv3,  ".xdata",   0)
    _QTD_FAKE_SIG(_qtd_dnv4,  ".xtls",
        "\x64\x65\x6E\x75\x76\x6F\x5F\x61\x74\x64\x00\x00\x00\x00\x00\x00")
    _QTD_FAKE_SIG(_qtd_sec,   ".dsstext", 0)
#endif

// ═══════════════════════════════════════════════════════════════════════
//  Compile-time seeding
// ═══════════════════════════════════════════════════════════════════════
constexpr uint32_t _qtd_fnv1a(const char* s, uint32_t h = 2166136261u) {
    return *s == '\0' ? h : _qtd_fnv1a(s + 1, (h ^ (uint8_t)*s) * 16777619u);
}

static constexpr uint32_t _QTD_FILE_HASH = _qtd_fnv1a(__FILE__);
static constexpr uint32_t _QTD_TIME_HASH = _qtd_fnv1a(__TIME__);

#define _QTD_CT_SEED  ((_QTD_FILE_HASH ^ _QTD_TIME_HASH                \
                       ^ ((uint32_t)__COUNTER__ * 2246822519u)          \
                       ^ ((uint32_t)__LINE__    * 3266489917u)) & 0xFFFFFFFFu)
#define _QTD_RND(lo, hi) \
    ((uint8_t)((lo) + (_QTD_CT_SEED % ((hi) - (lo) + 1u))))

// ═══════════════════════════════════════════════════════════════════════
//  Key derivation + byte-level encrypt / decrypt
// ═══════════════════════════════════════════════════════════════════════
constexpr uint8_t _qtd_derive_key(uint8_t base, size_t pos, uint32_t salt) {
    uint32_t k = (uint32_t)base;
    k ^= (uint32_t)(pos * 2654435761u);
    k ^= salt;
    k ^= k >> 16; k *= 0x85ebca6bu;
    k ^= k >> 13; k *= 0xc2b2ae35u;
    k ^= k >> 16;
    return (uint8_t)(k & 0xFF);
}

constexpr uint8_t _qtd_rol8(uint8_t v, uint8_t n) {
    n &= 7u;
    return (uint8_t)((v << n) | (v >> (8u - n)));
}
constexpr uint8_t _qtd_ror8(uint8_t v, uint8_t n) {
    n &= 7u;
    return (uint8_t)((v >> n) | (v << (8u - n)));
}

static volatile uint8_t _qtd_dec_mask = 0;

constexpr uint8_t _qtd_enc(uint8_t p, uint8_t k1, uint8_t k2,
                            size_t i, uint32_t salt) {
    const uint8_t dk1 = _qtd_derive_key(k1, i, salt);
    const uint8_t dk2 = _qtd_derive_key(k2, i, salt ^ 0xBEEFu);
    const uint8_t rot = (dk1 & 7u) | 1u;
    return (uint8_t)(_qtd_rol8((uint8_t)(p ^ dk1), rot) + dk2);
}

QTD_INLINE uint8_t _qtd_dec(uint8_t c, uint8_t k1, uint8_t k2,
                              size_t i, uint32_t salt) {
    const uint8_t rk1 = (uint8_t)(k1 ^ _qtd_dec_mask);
    const uint8_t rk2 = (uint8_t)(k2 ^ _qtd_dec_mask);
    const uint8_t dk1 = _qtd_derive_key(rk1, i, salt);
    const uint8_t dk2 = _qtd_derive_key(rk2, i, salt ^ 0xBEEFu);
    const uint8_t rot = (dk1 & 7u) | 1u;
    return (uint8_t)(_qtd_ror8((uint8_t)(c - dk2), rot) ^ dk1);
}

// ── Wide-char helpers ────────────────────────────────────────────────
// [NEW] Mã hoá / giải từng byte riêng trong một phần tử kiểu T.
// Hỗ trợ char (1B), wchar_t (2B/4B), char16_t (2B), char32_t (4B).
// Khi sizeof(T)==1 thì tương đương đúng với hàm byte cũ.
// Dùng uint64_t làm accumulator để tránh UB khi T là char signed.
// Với char (1B): b chỉ = 0, shift = 0 → tương đương cast byte cũ.
// Với wchar_t (2–4B), char16_t, char32_t: tích lũy từng byte.
template<typename T>
constexpr T _qtd_enc_t(T v, uint8_t k1, uint8_t k2,
                        size_t elem_idx, uint32_t salt) {
    uint64_t out = 0;
    for (size_t b = 0; b < sizeof(T); ++b) {
        // Cast v → uint64_t trước (unsigned, well-defined kể cả với char âm),
        // sau đó shift và truncate xuống uint8_t.
        const uint8_t byte_in  = static_cast<uint8_t>(
            (static_cast<uint64_t>(v) >> (b * 8u)) & 0xFFu);
        const uint8_t byte_out = _qtd_enc(byte_in, k1, k2,
                                          elem_idx * sizeof(T) + b, salt);
        out |= static_cast<uint64_t>(byte_out) << (b * 8u);
    }
    return static_cast<T>(out);
}

template<typename T>
QTD_INLINE T _qtd_dec_t(T v, uint8_t k1, uint8_t k2,
                          size_t elem_idx, uint32_t salt) {
    uint64_t out = 0;
    for (size_t b = 0; b < sizeof(T); ++b) {
        const uint8_t byte_in  = static_cast<uint8_t>(
            (static_cast<uint64_t>(v) >> (b * 8u)) & 0xFFu);
        const uint8_t byte_out = _qtd_dec(byte_in, k1, k2,
                                          elem_idx * sizeof(T) + b, salt);
        out |= static_cast<uint64_t>(byte_out) << (b * 8u);
    }
    return static_cast<T>(out);
}

// ═══════════════════════════════════════════════════════════════════════
//  MBA expressions
// ═══════════════════════════════════════════════════════════════════════
#if QTD_MBA_EXPRESSIONS
#   define MBA_XOR(a,b)  ((a) + (b) - 2*((a) & (b)))
#   define MBA_XOR2(a,b) (((a) | (b)) - ((a) & (b)))
#   define MBA_ADD(a,b)  (MBA_XOR((a),(b)) + 2*((a)&(b)))
#   define MBA_NOT(a)    (-(a) - 1)
#   define MBA_OR(a,b)   (MBA_ADD((a),(b)) - ((a)&(b)))
#   define MBA_AND(a,b)  ((MBA_ADD((a),(b)) - MBA_XOR((a),(b))) / 2)
#else
#   define MBA_XOR(a,b)  ((a)^(b))
#   define MBA_XOR2(a,b) ((a)^(b))
#   define MBA_ADD(a,b)  ((a)+(b))
#   define MBA_NOT(a)    (~(a))
#   define MBA_OR(a,b)   ((a)|(b))
#   define MBA_AND(a,b)  ((a)&(b))
#endif

// ═══════════════════════════════════════════════════════════════════════
//  Opaque predicates
// ═══════════════════════════════════════════════════════════════════════
static volatile uint64_t _qtd_op_n = 0x9E3779B97F4A7C15ULL;

static QTD_NOINLINE bool _qtd_pred_true() {
    volatile uint64_t n = _qtd_op_n;
    return ((n * (n + 1u)) & 1u) == 0u;
}
static QTD_NOINLINE bool _qtd_pred_false() {
    volatile uint64_t n = _qtd_op_n;
    return ((n * (n + 1u)) & 1u) == 1u;
}

#define _QTD_TRUE  (_qtd_pred_true())
#define _QTD_FALSE (_qtd_pred_false())

// ═══════════════════════════════════════════════════════════════════════
//  Indirect branching  (_QTD_IB)  +  stack-frame breaker (_QTD_BREAK_FRAME)
//
//  _QTD_IB:
//    • KHÔNG bao giờ thực thi (điều kiện luôn false ở runtime)
//    • Phá IDA/Ghidra linear-sweep: tạo byte rác hoặc indirect call
//      mà disassembler không thể resolve tĩnh
//
//  _QTD_BREAK_FRAME:
//    • Làm IDA mất theo dõi delta RSP/SP → stack frame sai
//    • x64/x86 GCC: sub/add rsp tạo delta giả
//    • ARM64  GCC: sub/add sp tạo delta giả
//    • MSVC       : volatile _alloca với kích thước runtime opaque
// ═══════════════════════════════════════════════════════════════════════
#if QTD_INDIRECT_BRANCHING

// ── GCC/Clang · x86-64 ───────────────────────────────────────────────
// Kỹ thuật gốc: jz qua 1 byte 0xE8 (prefix CALL giả).
// IDA linear-sweep nhìn thấy 0xE8 và decode sai 4 byte tiếp theo.
// L2: push+indirect-jmp (br [rax]) qua volatile rax → IDA không resolve.
#   if defined(_QTD_ARCH_X64) && defined(_QTD_GNUC)

#       define _QTD_IB_L1                                               \
            __asm__ volatile(                                           \
                "xor %%rax, %%rax\n\t"                                  \
                "jz  1f\n\t"                                            \
                ".byte 0xE8\n\t"       /* dead CALL prefix — rác 1B */ \
                "1:" : : : "rax");

#       define _QTD_IB_L2                                               \
            __asm__ volatile(                                           \
                "lea 1f(%%rip), %%rax\n\t"                              \
                "push %%rax\n\t"                                        \
                "xor %%rbx, %%rbx\n\t"                                  \
                "jz  2f\n\t"                                            \
                ".byte 0xFF, 0x20\n\t" /* dead jmp [rax] — IDA lost */ \
                "2:\n\t"                                                \
                "pop %%rax\n\t"                                         \
                "1:" : : : "rax", "rbx");

#       define _QTD_IB  _QTD_IB_L1 _QTD_IB_L2

        // sub/add rsp: tạo delta giả khiến IDA tính sai frame size
        // Ghi chú: bỏ "rsp" khỏi clobber (deprecated GCC ≥ 14);
        // "memory" đủ để ngăn compiler reorder, asm vẫn in/out rsp.
#       define _QTD_BREAK_FRAME()                                       \
            __asm__ volatile(                                           \
                "sub $0x80, %%rsp\n\t"                                  \
                "add $0x80, %%rsp\n\t"                                  \
                : : : "memory")

// ── GCC/Clang · x86-32 ───────────────────────────────────────────────
#   elif defined(_QTD_ARCH_X86) && defined(_QTD_GNUC)

#       define _QTD_IB                                                  \
            __asm__ volatile(                                           \
                "xor %%eax, %%eax\n\t"                                  \
                "jz  1f\n\t"                                            \
                ".byte 0xE8\n\t"       /* dead CALL prefix */          \
                "1:");

#       define _QTD_BREAK_FRAME()                                       \
            __asm__ volatile(                                           \
                "sub $0x40, %%esp\n\t"                                  \
                "add $0x40, %%esp\n\t"                                  \
                : : : "memory")

// ── GCC/Clang · ARM64 ────────────────────────────────────────────────
// [NEW] adr x16, 1f  → load địa chỉ label 1 vào x16
//       br  x16      → indirect branch (IDA không biết target tĩnh)
//       .long dead   → 4 byte chết giữa br và label 1:
//                       IDA linear-sweep fall-through sẽ decode sai
#   elif defined(_QTD_ARCH_ARM64) && defined(_QTD_GNUC)

#       define _QTD_IB                                                  \
            __asm__ volatile(                                           \
                "adr  x16, 1f\n\t"                                      \
                "br   x16\n\t"                                          \
                ".long 0xD63F0200\n\t" /* dead blr x16 — rác 4B */    \
                "1:\n\t"                                                \
                : : : "x16")

#       define _QTD_BREAK_FRAME()                                       \
            __asm__ volatile(                                           \
                "sub sp, sp, #16\n\t"                                   \
                "add sp, sp, #16\n\t"                                   \
                : : : "memory")

// ── MSVC · x64 hoặc ARM64 (không có inline asm) ──────────────────────
// [NEW] Chiến lược thuần C++:
//   _QTD_IB:
//     1. Indirect call qua volatile function pointer — CFG không resolve
//     2. __debugbreak() trong dead branch — INT3/BRK gây nhầm lẫn
//        exception-path analysis của decompiler
//   _QTD_BREAK_FRAME:
//     _alloca với kích thước runtime-opaque → IDA mất tracking RSP delta
#   elif defined(_QTD_MSVC)

    QTD_NOINLINE static void _qtd_ib_sink() { /* opaque no-op target */ }
    static volatile void(*_qtd_ib_vfp)() = _qtd_ib_sink;

#       define _QTD_IB                                                  \
            do {                                                        \
                if (_qtd_pred_false()) {                                \
                    _qtd_ib_vfp();   /* indirect call — unresolvable */ \
                    __debugbreak();  /* INT3/BRK trong dead code */     \
                }                                                       \
            } while(0)

#       define _QTD_BREAK_FRAME()                                       \
            do {                                                        \
                volatile int _qtd_sz =                                  \
                    (int)((_qtd_op_n & 0xFu) + 16u); /* opaque */     \
                volatile char* _qtd_p =                                 \
                    (volatile char*)_alloca(_qtd_sz);                  \
                _qtd_p[0] = 0;   /* write buộc compiler không xoá */   \
            } while(0)

// ── Fallback (platform chưa hỗ trợ) ──────────────────────────────────
#   else
#       define _QTD_IB            ((void)0)
#       define _QTD_BREAK_FRAME() ((void)0)
#   endif

#else  // QTD_INDIRECT_BRANCHING == 0
#   define _QTD_IB            ((void)0)
#   define _QTD_BREAK_FRAME() ((void)0)
#endif

// ═══════════════════════════════════════════════════════════════════════
//  Anti-debug
// ═══════════════════════════════════════════════════════════════════════
#if QTD_ANTI_DEBUG

#   if defined(_QTD_LINUX)
#       include <sys/ptrace.h>
        static QTD_NOINLINE bool _qtd_is_debugged() {
            return ptrace(PTRACE_TRACEME, 0, 0, 0) == -1;
        }

#   elif defined(_QTD_WINDOWS) && !QTD_KERNEL_MODE
#       ifndef _WINDOWS_
#           include <windows.h>
#       endif
        static QTD_NOINLINE bool _qtd_is_debugged() {
            if (IsDebuggerPresent()) return true;
            volatile uint8_t ntgf = 0;
            // [FIX] Tách GCC vs MSVC để tránh lỗi biên dịch MSVC
            // (MSVC x64/ARM64 không hỗ trợ inline asm)
#           if defined(_QTD_GNUC)
                // GCC/Clang: đọc PEB.NtGlobalFlag qua segment register
#               if defined(_QTD_ARCH_X64)
                    __asm__ volatile(
                        "mov %%gs:0x60, %%rax\n\t"
                        "movb 0x68(%%rax), %0"
                        : "=r"(ntgf) : : "rax");
#               elif defined(_QTD_ARCH_X86)
                    __asm__ volatile(
                        "mov %%fs:0x30, %%eax\n\t"
                        "movb 0x68(%%eax), %0"
                        : "=r"(ntgf) : : "eax");
#               endif
#           elif defined(_QTD_MSVC)
                // [FIX] MSVC: dùng intrinsic __readgsqword / __readfsdword
                // thay cho inline asm không tương thích
#               if defined(_QTD_ARCH_X64)
                    // GS:0x60 → PEB*,  PEB+0x68 → NtGlobalFlag
                    ntgf = *(volatile uint8_t*)(__readgsqword(0x60) + 0x68);
#               elif defined(_QTD_ARCH_X86)
                    ntgf = *(volatile uint8_t*)(
                               (uintptr_t)__readfsdword(0x30) + 0x68);
#               elif defined(_QTD_ARCH_ARM64)
                    // ARM64 Windows: IsDebuggerPresent() đã cover trường hợp
                    // chính. NtCurrentTeb() cần thêm header nội bộ, bỏ qua.
                    ntgf = 0;
#               endif
#           endif
            return (ntgf & 0x70) != 0;
        }

#   elif defined(_QTD_APPLE)
#       include <sys/types.h>
#       include <sys/sysctl.h>
        static QTD_NOINLINE bool _qtd_is_debugged() {
            int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
            struct kinfo_proc info{};
            size_t sz = sizeof(info);
            sysctl(mib, 4, &info, &sz, nullptr, 0);
            return (info.kp_proc.p_flag & P_TRACED) != 0;
        }

#   else
        static QTD_NOINLINE bool _qtd_is_debugged() { return false; }
#   endif

#   define QTD_ANTI_DEBUG_CHECK() do {                                  \
        if (_qtd_is_debugged()) {                                       \
            volatile int* _p = nullptr; (void)*_p;                     \
        }                                                               \
    } while(0)

#else
#   define QTD_ANTI_DEBUG_CHECK() ((void)0)
#endif

// ─────────────────────────────────────────────────────────────────────
//  Control-flow helpers
// ─────────────────────────────────────────────────────────────────────
#define _QTD_BLOCK_COND(c, blk)  if (c) { _QTD_IB; blk; }
#define _QTD_BLOCK_TRUE(blk)     _QTD_BLOCK_COND(_QTD_TRUE,  blk)
#define _QTD_BLOCK_FALSE(blk)    _QTD_BLOCK_COND(_QTD_FALSE, blk)

// [NEW] _QTD_BREAK_FRAME() thêm vào _qtd_int_proxy để phá frame IDA
static QTD_INLINE int _qtd_int_proxy(long long v) {
    _QTD_IB;
    _QTD_BREAK_FRAME();
    volatile long long a = v;
    _QTD_BLOCK_FALSE(return (int)(a ^ 0xDEAD);)
    _QTD_BLOCK_TRUE( if (_QTD_TRUE) return (int)a; )
    return (int)a;
}

// ═══════════════════════════════════════════════════════════════════════
//  namespace qtdenc — obfuscator / tl_decryptor
//  [FIX/NEW] Dùng _qtd_enc_t / _qtd_dec_t thay vì cast uint8_t trực tiếp
//            → hỗ trợ wchar_t, char16_t, char32_t (và raw string tương ứng)
// ═══════════════════════════════════════════════════════════════════════
namespace qtdenc {

    template<typename T>
    using clean_t = std::remove_const_t<std::remove_reference_t<T>>;

    // getsize: trả về N cho mảng, 1 cho scalar
    template<typename T, size_t N>
    constexpr size_t getsize(const T(&)[N]) { return N; }
    template<typename T>
    constexpr size_t getsize(T)             { return 1; }

    // gettype: suy ra kiểu phần tử
    template<typename T, size_t N>
    constexpr T gettype(const T(&)[N]);
    template<typename T>
    constexpr T gettype(T);

    // ── obfuscator ─────────────────────────────────────────────────────
    // Hỗ trợ đầy đủ: char, wchar_t, char16_t, char32_t
    // Mọi string literal (kể cả L"...", u"...", U"...", R"(...)",
    // LR"(...)"...) đều được mã hoá từng byte của mỗi phần tử.
    template<class T, size_t SZ, uint8_t K1, uint8_t K2, uint32_t SALT>
    class obfuscator {
    public:
        T    m_data[SZ]{};
        bool decrypted = false;

        constexpr obfuscator(const T* src) {
            for (size_t i = 0; i < SZ; ++i)
                m_data[i] = _qtd_enc_t<T>(src[i], K1, K2, i, SALT);
        }
        constexpr obfuscator(T v) {
            m_data[0] = _qtd_enc_t<T>(v, K1, K2, 0, SALT);
        }

        QTD_INLINE T* decrypt() {
            _QTD_IB;
            _QTD_BREAK_FRAME();
            if (!decrypted) {
                for (size_t i = 0; i < SZ; ++i) {
#if QTD_CFLOW_CONST_DECRYPTION
                    _QTD_BLOCK_FALSE(
                        volatile uint8_t _x = (uint8_t)(i * 7u); (void)_x;)
                    _QTD_BLOCK_TRUE(
#endif
                        m_data[i] = _qtd_dec_t<T>(m_data[i], K1, K2, i, SALT);
#if QTD_CFLOW_CONST_DECRYPTION
                    )
#endif
                }
                decrypted = true;
            }
            return m_data;
        }

        QTD_INLINE operator T*() { return decrypt(); }
        QTD_INLINE operator T()  { return decrypt()[0]; }
    };

    // ── tl_decryptor (thread-local mode) ─────────────────────────────
    template<class T, size_t SZ, uint8_t K1, uint8_t K2, uint32_t SALT>
    class tl_decryptor {
    public:
        T    m_data[SZ]{};
        bool decrypted = false;

        QTD_INLINE tl_decryptor(const obfuscator<T,SZ,K1,K2,SALT>& src) {
            for (size_t i = 0; i < SZ; ++i)
                m_data[i] = src.m_data[i];
        }

        QTD_INLINE T* decrypt() {
            if (!decrypted) {
                for (size_t i = 0; i < SZ; ++i)
                    m_data[i] = _qtd_dec_t<T>(m_data[i], K1, K2, i, SALT);
                decrypted = true;
            }
            return m_data;
        }
        QTD_INLINE operator T*() { return decrypt(); }
        QTD_INLINE operator T()  { return decrypt()[0]; }
    };

} // namespace qtdenc

// ═══════════════════════════════════════════════════════════════════════
//  QTDENC — macro chính mã hoá string literal
//
//  Sử dụng:
//    QTDENC("hello")          → const char*
//    QTDENC(L"wide")          → wchar_t*    [NEW]
//    QTDENC(u"utf16")         → char16_t*   [NEW]
//    QTDENC(U"utf32")         → char32_t*   [NEW]
//    QTDENC(R"(raw\nstring)") → const char* [raw string tự động]
//    QTDENC(LR"(wide raw)")   → wchar_t*    [NEW]
// ═══════════════════════════════════════════════════════════════════════
#if QTD_CONST_ENCRYPTION

#   define _QTDENC_NORMAL(x)                                             \
        ([]() -> auto* {                                                 \
            constexpr uint32_t _s  = _QTD_CT_SEED;                      \
            constexpr uint8_t  _k1 = (uint8_t)(1u   + (_s         % 126u)); \
            constexpr uint8_t  _k2 = (uint8_t)(128u + ((_s >> 8u) % 126u)); \
            constexpr uint32_t _sl = _QTD_FILE_HASH ^ (_s >> 4u);       \
            using _T   = qtdenc::clean_t<decltype(qtdenc::gettype(x))>; \
            constexpr size_t _N   = qtdenc::getsize(x);                  \
            using _OBF = qtdenc::obfuscator<_T, _N, _k1, _k2, _sl>;     \
            constexpr static _OBF _enc(x);                               \
            static _OBF _dec = _enc;                                     \
            return _dec.decrypt();                                       \
        }())

#   define _QTDENC_THREADLOCAL(x)                                        \
        ([]() -> auto* {                                                 \
            constexpr uint32_t _s  = _QTD_CT_SEED;                      \
            constexpr uint8_t  _k1 = (uint8_t)(1u   + (_s         % 126u)); \
            constexpr uint8_t  _k2 = (uint8_t)(128u + ((_s >> 8u) % 126u)); \
            constexpr uint32_t _sl = _QTD_FILE_HASH ^ (_s >> 4u);       \
            using _T   = qtdenc::clean_t<decltype(qtdenc::gettype(x))>; \
            constexpr size_t _N   = qtdenc::getsize(x);                  \
            using _OBF = qtdenc::obfuscator<_T, _N, _k1, _k2, _sl>;     \
            using _TLD = qtdenc::tl_decryptor<_T, _N, _k1, _k2, _sl>;   \
            constexpr static _OBF _enc(x);                               \
            thread_local _TLD _dec(_enc);                                \
            return _dec.decrypt();                                       \
        }())

#   if QTD_CONST_ENCRYPT_THREADLOCAL
#       define QTDENC(x) _QTDENC_THREADLOCAL(x)
#   else
#       define QTDENC(x) _QTDENC_NORMAL(x)
#   endif

#else
#   define QTDENC(x) (x)
#endif

// ─────────────────────────────────────────────────────────────────────
//  QTDENC_INT
// ─────────────────────────────────────────────────────────────────────
#define QTDENC_INT(x)                                               \
    ([&]() -> decltype(x) {                                         \
        constexpr auto _m = (decltype(x))_QTD_RND(1, 0x7E);        \
        constexpr auto _a = (decltype(x))((x) ^ _m);               \
        return (decltype(x))MBA_XOR(_a, _m);                        \
    }())

// ═══════════════════════════════════════════════════════════════════════
//  Bit-cast helpers — constexpr-compatible trên mọi compiler
//
//  [FIX] MSVC không có __builtin_bit_cast.
//  Thứ tự ưu tiên:
//    1. GCC/Clang  → __builtin_bit_cast   (constexpr, không cần C++20)
//    2. C++20 any  → std::bit_cast        (constexpr, tiêu chuẩn)
//    3. MSVC C++14/17 → union type-pun    (Microsoft extension, constexpr OK)
// ═══════════════════════════════════════════════════════════════════════
#if defined(__GNUC__) || defined(__clang__)
    // GCC ≥ 10, Clang ≥ 9
#   define _QTD_F2U(f)  (__builtin_bit_cast(uint32_t, (float)(f)))
#   define _QTD_D2U(d)  (__builtin_bit_cast(uint64_t, (double)(d)))
#   define _QTD_U2F(u)  (__builtin_bit_cast(float,    (uint32_t)(u)))
#   define _QTD_U2D(u)  (__builtin_bit_cast(double,   (uint64_t)(u)))

#elif defined(__cpp_lib_bit_cast)
    // C++20 với std::bit_cast (MSVC 2019 16.6+/std:c++20)
#   include <bit>
#   define _QTD_F2U(f)  (::std::bit_cast<uint32_t>((float)(f)))
#   define _QTD_D2U(d)  (::std::bit_cast<uint64_t>((double)(d)))
#   define _QTD_U2F(u)  (::std::bit_cast<float>((uint32_t)(u)))
#   define _QTD_U2D(u)  (::std::bit_cast<double>((uint64_t)(u)))

#else
    // [FIX] MSVC C++14/17 fallback: union type-pun.
    // MSVC cho phép đọc union member khác member vừa ghi trong constexpr
    // (Microsoft extension, không phải UB trong MSVC).
    namespace _qtd_bp {
        union _f32 {
            float    f; uint32_t u;
            constexpr explicit _f32(float    x) : f(x) {}
            constexpr explicit _f32(uint32_t x) : u(x) {}
        };
        union _f64 {
            double   d; uint64_t u;
            constexpr explicit _f64(double   x) : d(x) {}
            constexpr explicit _f64(uint64_t x) : u(x) {}
        };
    }
#   define _QTD_F2U(f)  (_qtd_bp::_f32((float)(f)).u)
#   define _QTD_D2U(d)  (_qtd_bp::_f64((double)(d)).u)
#   define _QTD_U2F(u)  (_qtd_bp::_f32((uint32_t)(u)).f)
#   define _QTD_U2D(u)  (_qtd_bp::_f64((uint64_t)(u)).d)
#endif

// ── QTDENC_FLOAT ──────────────────────────────────────────────────────
// [FIX] Hoạt động trên MSVC (không phụ thuộc __builtin_bit_cast).
// Bit pattern của float được XOR với mask compile-time;
// mask được XOR lại ở runtime qua MBA để che giấu giá trị thật.
#define QTDENC_FLOAT(x)                                             \
    ([&]() -> float {                                               \
        constexpr uint32_t _fb = _QTD_F2U((float)(x));             \
        constexpr uint32_t _fm = (uint32_t)_QTD_RND(1, 0x7E);     \
        constexpr uint32_t _fe = _fb ^ _fm;                        \
        volatile  uint32_t _fd = (uint32_t)MBA_XOR(_fe, _fm);     \
        return _QTD_U2F((uint32_t)_fd);                            \
    }())

// ── QTDENC_DOUBLE ─────────────────────────────────────────────────────
// [NEW] Tương tự QTDENC_FLOAT nhưng cho double (64-bit).
// Mask 64-bit được tạo từ hai _QTD_RND độc lập (mỗi cái dùng __COUNTER__
// khác nhau → seed khác nhau).
#define QTDENC_DOUBLE(x)                                            \
    ([&]() -> double {                                              \
        constexpr uint64_t _db = _QTD_D2U((double)(x));            \
        constexpr uint64_t _dm =                                    \
            ((uint64_t)_QTD_RND(1, 0xFE) << 32u) |                \
             (uint64_t)_QTD_RND(1, 0xFE);                          \
        constexpr uint64_t _de = _db ^ _dm;                        \
        volatile  uint64_t _dd = (uint64_t)MBA_XOR(_de, _dm);     \
        return _QTD_U2D((uint64_t)_dd);                            \
    }())

static void _qtd_dc1(){}  static void _qtd_dc2(){}
static void _qtd_dc3(){}  static void _qtd_dc4(){}
static void _qtd_dc5(){}  static void _qtd_dc6(){}
static void _qtd_dc7(){}  static void _qtd_dc8(){}
static void _qtd_dc9(){}  static void _qtd_dc10(){}

#define HIDE_CALL(fn, ...)                                          \
    ([&]() {                                                        \
        typedef decltype(&fn) _qtd_ft;                              \
        volatile _qtd_ft _arr[] = {                                 \
            (_qtd_ft)_qtd_dc1,  (_qtd_ft)_qtd_dc2,                 \
            &fn,                 /* index 2 — thật */               \
            (_qtd_ft)_qtd_dc3,  (_qtd_ft)_qtd_dc4,                 \
            (_qtd_ft)_qtd_dc5,  (_qtd_ft)_qtd_dc6,                 \
            (_qtd_ft)_qtd_dc7,  (_qtd_ft)_qtd_dc8,                 \
            (_qtd_ft)_qtd_dc9,  (_qtd_ft)_qtd_dc10                 \
        };                                                          \
        return _arr[QTDENC_INT(2)](__VA_ARGS__);                    \
    }())

#if defined(_QTD_LINUX) || defined(_QTD_APPLE)
#   include <dlfcn.h>
#   define CALL_EXPORT(sym, ftype, ...) \
        (reinterpret_cast<ftype>(dlsym(RTLD_DEFAULT, QTDENC(sym))))(__VA_ARGS__)
#elif defined(_QTD_WINDOWS) && !QTD_KERNEL_MODE
#   ifndef _WINDOWS_
#       include <windows.h>
#   endif
#   define CALL_EXPORT(lib, sym, ftype, ...) \
        (reinterpret_cast<ftype>(                                    \
            GetProcAddress(GetModuleHandleA(QTDENC(lib)), QTDENC(sym)) \
        ))(__VA_ARGS__)
#endif

#if QTD_CFLOW_BRANCHING
#   define if(x)     if (_QTD_TRUE) if (_qtd_int_proxy((long long)(x)) && _QTD_TRUE)
#   define for(x)    for (volatile int _qtd_cfi=0; _qtd_cfi<_qtd_int_proxy(1); _qtd_cfi++) for(x)
#   define while(x)  while(_qtd_int_proxy((long long)(x)) && _QTD_TRUE)
#   define switch(x) switch((int)(_qtd_int_proxy((long long)(x))))
#   define return    for (volatile int _qtd_cfr=0; _qtd_cfr<_qtd_int_proxy(1); _qtd_cfr++) return
#   define else      else _QTD_BLOCK_FALSE(_qtd_int_proxy(0);) else
#endif

// ═══════════════════════════════════════════════════════════════════════
//  Inline string helpers
// ═══════════════════════════════════════════════════════════════════════
#if QTD_INLINE_STD

    static QTD_INLINE void qtd_strcpy(char* d, const char* s) {
        while ((*d++ = *s++));
    }
    static QTD_INLINE size_t qtd_strlen(const char* s) {
        const char* p = s; while (*p) p++; return (size_t)(p - s);
    }
    static QTD_INLINE int qtd_strcmp(const char* a, const char* b) {
        while (*a == *b++) if (*a++ == '\0') return 0;
        return *(const unsigned char*)a - *(const unsigned char*)--b;
    }
    static QTD_INLINE int qtd_strncmp(const char* a, const char* b, size_t n) {
        unsigned char u1, u2;
        while (n-- > 0) {
            u1 = (unsigned char)*a++;
            u2 = (unsigned char)*b++;
            if (u1 != u2) return (int)u1 - (int)u2;
            if (u1 == '\0') return 0;
        }
        return 0;
    }
    static QTD_INLINE char* qtd_strstr(const char* s, const char* f) {
        if (!*f) return (char*)s;
        for (; *s; ++s) {
            const char *p = s, *q = f;
            while (*p && *q && *p == *q) { ++p; ++q; }
            if (!*q) return (char*)s;
        }
        return nullptr;
    }
    static QTD_INLINE char* qtd_strncat(char* dest, const char* src, size_t n) {
        char* p = dest;
        while (*p) p++;
        while (n-- > 0 && *src) *p++ = *src++;
        *p = '\0';
        return dest;
    }
    static QTD_INLINE unsigned long qtd_strtoul_hex(const char* s, char** end) {
        unsigned long r = 0;
        while (*s) {
            char c = *s++;
            if      (c >= '0' && c <= '9') r = r*16 + (unsigned long)(c-'0');
            else if (c >= 'a' && c <= 'f') r = r*16 + (unsigned long)(c-'a'+10);
            else if (c >= 'A' && c <= 'F') r = r*16 + (unsigned long)(c-'A'+10);
            else break;
        }
        if (end) *end = (char*)s;
        return r;
    }
    static QTD_INLINE void* qtd_memcpy(void* dst, const void* src, size_t n) {
        uint8_t* d = (uint8_t*)dst;
        const uint8_t* s_ = (const uint8_t*)src;
        while (n--) *d++ = *s_++;
        return dst;
    }
    static QTD_INLINE void* qtd_memset(void* dst, int val, size_t n) {
        uint8_t* d = (uint8_t*)dst;
        while (n--) *d++ = (uint8_t)val;
        return dst;
    }

    // [NEW] Wide-char strlen (wchar_t / char16_t / char32_t)
    static QTD_INLINE size_t qtd_wcslen(const wchar_t* s) {
        const wchar_t* p = s; while (*p) p++; return (size_t)(p - s);
    }

#endif // QTD_INLINE_STD

static void _qtd_wm_hook(const char*) {}
typedef volatile void(*_qtd_wm_t)(const char*);
static volatile _qtd_wm_t _qtd_wm = (_qtd_wm_t)_qtd_wm_hook;

#define QTD_WATERMARK(...)                                           \
    do {                                                             \
        const char* _d[] = {__VA_ARGS__};                            \
        for (volatile int _i = 0;                                    \
             _i < (int)(sizeof(_d)/sizeof(*_d)); _i++)               \
            _qtd_wm(_d[_i]);                                         \
    } while(0)

static QTD_NOINLINE void _qtd_decoy_main() {
    QTD_WATERMARK(
        "Protected by QUOCTOANDEV",
        "Developer by @quoctoansieudz", nullptr
    );
}

#endif // QUOCTOANDEV_H

#undef if
#undef for
#undef while
#undef switch
#undef return
#undef else