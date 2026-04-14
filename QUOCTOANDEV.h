/*
================================================================================
   ____  __  ______  ________________  ___    _   ______  _______    __  __  __
  / __ \/ / / / __ \/ ____/_  __/ __ \/   |  / | / / __ \/ ____/ |  / / / / / /
 / / / / / / / / / / /     / / / / / / /| | /  |/ / / / / __/  | | / / / /_/ / 
/ /_/ / /_/ / /_/ / /___  / / / /_/ / ___ |/ /|  / /_/ / /___  | |/ / / __  /  
\___\_\____/\____/\____/ /_/  \____/_/  |_/_/ |_/_____/_____/  |___(_)_/ /_/   
                                                                               
================================================================================

@author QuocToanDev

Copyright (c) 2026 QuocToanDev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

================================================================================
*/

#ifndef QUOCTOANDEV_H
#define QUOCTOANDEV_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <cstring>

typedef uint8_t  qtd_uint8;
typedef uint32_t qtd_uint32;
typedef uint64_t qtd_uint64;
typedef size_t   qtd_size;

#ifdef _MSC_VER
    #define QTD_FORCEINLINE __forceinline
    #define QTD_INLINE      __inline
#else
    #define QTD_FORCEINLINE __attribute__((always_inline)) inline
    #define QTD_INLINE      inline
#endif

#if defined(_WIN32) || defined(_WIN64)
    #if defined(_WIN64)
        #define QTD_ENV64
    #else
        #define QTD_ENV32
    #endif
#elif defined(__GNUC__)
    #if defined(__x86_64__) || defined(__ppc64__) || defined(__aarch64__)
        #define QTD_ENV64
    #else
        #define QTD_ENV32
    #endif
#endif

namespace qtd_crypto {

    static constexpr qtd_size COMPILE_BASE_KEY = 
        ((__TIME__[7] - '0') +
         (__TIME__[6] - '0') * 10 +
         (__TIME__[4] - '0') * 60 +
         (__TIME__[3] - '0') * 600 +
         (__TIME__[1] - '0') * 3600 +
         (__TIME__[0] - '0') * 36000);

    template<qtd_uint32 seed, qtd_size iterations>
    class XorShift32 {
        static constexpr qtd_uint32 x = seed ^ (seed << 13);
        static constexpr qtd_uint32 y = x ^ (x >> 17);
        static constexpr qtd_uint32 z = y ^ (y << 5);
    public:
        static constexpr qtd_uint32 value = XorShift32<z, iterations - 1>::value;
    };

    template<qtd_uint32 seed>
    class XorShift32<seed, 0> {
    public:
        static constexpr qtd_uint32 value = seed;
    };

    template<qtd_uint64 seed, qtd_size iterations>
    class XorShift64 {
        static constexpr qtd_uint64 x = seed ^ (seed << 13);
        static constexpr qtd_uint64 y = x ^ (x >> 7);
        static constexpr qtd_uint64 z = y ^ (y << 17);
    public:
        static constexpr qtd_uint64 value = XorShift64<z, iterations - 1>::value;
    };

    template<qtd_uint64 seed>
    class XorShift64<seed, 0> {
    public:
        static constexpr qtd_uint64 value = seed;
    };

    template<qtd_size key>
    static QTD_FORCEINLINE constexpr qtd_uint8 xor_encrypt(qtd_uint8 byte, qtd_size index) {
        return static_cast<qtd_uint8>(byte ^ ((key * 7) + index));
    }

    template<qtd_size key>
    static QTD_FORCEINLINE constexpr qtd_uint8 rot_encrypt(qtd_uint8 byte, qtd_size rot_amount) {
        qtd_uint8 amount = static_cast<qtd_uint8>(rot_amount % 8);
        return (byte << amount) | (byte >> (8 - amount));
    }

    template<qtd_size key>
    static QTD_FORCEINLINE constexpr qtd_uint8 add_encrypt(qtd_uint8 byte, qtd_size index) {
        return static_cast<qtd_uint8>(byte + ((key * 11 + index) & 0xFF));
    }

    template<qtd_size key>
    static QTD_FORCEINLINE constexpr qtd_uint8 encrypt_byte_3layer(
        qtd_uint8 byte, 
        qtd_size index
    ) {
        qtd_uint8 layer1 = xor_encrypt<key>(byte, index);
        qtd_uint8 layer2 = rot_encrypt<key>(layer1, key % 8);
        qtd_uint8 layer3 = add_encrypt<key>(layer2, index);
        return layer3;
    }

    template<qtd_size key>
    static QTD_FORCEINLINE constexpr qtd_uint8 decrypt_byte_3layer(
        qtd_uint8 encrypted, 
        qtd_size index
    ) {
        qtd_uint8 delayer3 = static_cast<qtd_uint8>(encrypted - ((key * 11 + index) & 0xFF));
        qtd_uint8 delayer2 = (delayer3 >> (key % 8)) | (delayer3 << (8 - (key % 8)));
        qtd_uint8 delayer1 = static_cast<qtd_uint8>(delayer2 ^ ((key * 7) + index));
        return delayer1;
    }

    template<qtd_size... Ints>
    struct index_sequence {
        using type = index_sequence;
        using value_type = qtd_size;
        static constexpr qtd_size size() noexcept { return sizeof...(Ints); }
    };

    template<class Seq1, class Seq2>
    struct merge_and_renumber;

    template<qtd_size... I1, qtd_size... I2>
    struct merge_and_renumber<index_sequence<I1...>, index_sequence<I2...>>
        : index_sequence<I1..., (sizeof...(I1) + I2)...>
    { };

    template<qtd_size N>
    struct make_index_sequence
        : merge_and_renumber<typename make_index_sequence<N / 2>::type,
                            typename make_index_sequence<N - N / 2>::type>
    { };

    template<> struct make_index_sequence<0> : index_sequence<> { };
    template<> struct make_index_sequence<1> : index_sequence<0> { };

    template<typename T, qtd_size array_size, qtd_size counter>
    class EncryptedConstant {
    private:
        static constexpr qtd_size encryption_key = 
            XorShift64<(counter ^ COMPILE_BASE_KEY), (counter % 32)>::value;
        
        static constexpr qtd_size buffer_size = 
            ((array_size * sizeof(T) + 15) & ~15) + 
            ((encryption_key % 16) + 1);
        
        alignas(16) qtd_uint8 encrypted_data[buffer_size];

    public:
        template<qtd_size... indices>
        QTD_FORCEINLINE constexpr EncryptedConstant(
            const T(&source)[array_size],
            index_sequence<indices...>
        ) : encrypted_data{
            encrypt_byte_3layer<encryption_key>(
                (reinterpret_cast<const qtd_uint8*>(&source))[indices], 
                indices
            )...
        } { }

        QTD_FORCEINLINE const T* decrypt() {
            qtd_uint8* buffer = encrypted_data;
            qtd_size buffer_idx = 0;
            qtd_size data_size = array_size * sizeof(T);

            for (qtd_size i = 0; i < data_size; ++i) {
                buffer[i] = decrypt_byte_3layer<encryption_key>(buffer[i], i);
            }

            return reinterpret_cast<const T*>(buffer);
        }
    };

    template<typename T, qtd_size size>
    static QTD_FORCEINLINE constexpr qtd_size _array_size(const T(&)[size]) { return size; }

    template<typename T>
    static QTD_FORCEINLINE constexpr qtd_size _array_size(T) { return 0; }

    template<typename T, qtd_size size>
    static inline T _get_type(const T(&)[size]);

    template<typename T>
    static inline T _get_type(T);
}

namespace qtd_runtime {
    class StringProtection {
    public:
        static QTD_FORCEINLINE qtd_uint8* encrypt_string(
            const char* plaintext, 
            qtd_size length,
            qtd_uint32 key
        ) {
            qtd_uint8* encrypted = (qtd_uint8*)malloc(length);
            if (!encrypted) return nullptr;
            
            for (qtd_size i = 0; i < length; ++i) {
                
                qtd_uint8 byte = static_cast<qtd_uint8>(plaintext[i]);
                byte = static_cast<qtd_uint8>(byte ^ ((key >> ((i % 4) * 8)) & 0xFF));
                
                qtd_uint8 rot_amount = static_cast<qtd_uint8>((key + i) % 8);
                byte = (byte << rot_amount) | (byte >> (8 - rot_amount));
                
                byte = static_cast<qtd_uint8>(byte + ((key * 3 + i) & 0xFF));
                
                encrypted[i] = byte;
            }
            
            return encrypted;
        }

        static QTD_FORCEINLINE char* decrypt_string(
            qtd_uint8* encrypted, 
            qtd_size length,
            qtd_uint32 key
        ) {
            char* decrypted = (char*)malloc(length + 1);
            if (!decrypted) return nullptr;

            for (qtd_size i = 0; i < length; ++i) {
                qtd_uint8 byte = encrypted[i];
                
                byte = static_cast<qtd_uint8>(byte - ((key * 3 + i) & 0xFF));
                
                qtd_uint8 rot_amount = static_cast<qtd_uint8>((key + i) % 8);
                byte = (byte >> rot_amount) | (byte << (8 - rot_amount));
                
                byte = static_cast<qtd_uint8>(byte ^ ((key >> ((i % 4) * 8)) & 0xFF));
                
                decrypted[i] = static_cast<char>(byte);
            }

            decrypted[length] = '\0';
            return decrypted;
        }

        static QTD_FORCEINLINE void secure_free(void* ptr) {
            if (ptr) {
                memset(ptr, 0, 256);
                free(ptr);
            }
        }
    };

    class MBAObfuscation {
    public:
        static QTD_FORCEINLINE qtd_uint32 add_obfuscated(qtd_uint32 a, qtd_uint32 b) {
            return ((a ^ b) + ((a & b) << 1));
        }

        static QTD_FORCEINLINE qtd_uint32 sub_obfuscated(qtd_uint32 a, qtd_uint32 b) {
            return ((a ^ b) - ((~a & b) << 1));
        }

        static QTD_FORCEINLINE qtd_uint32 mul_obfuscated(qtd_uint32 a, qtd_uint32 b) {
            return ((a << 1) + a) + (b - (b >> 2));
        }

        static QTD_FORCEINLINE qtd_uint32 xor_obfuscated(qtd_uint32 a, qtd_uint32 b) {
            return ((a | b) - (a & b));
        }

        static QTD_FORCEINLINE qtd_uint32 and_obfuscated(qtd_uint32 a, qtd_uint32 b) {
            return ((a & b) ^ ((a ^ b) & a));
        }

        static QTD_FORCEINLINE qtd_uint32 or_obfuscated(qtd_uint32 a, qtd_uint32 b) {
            return ((a | b) ^ ((a ^ b) & b));
        }
    };

    typedef void (*qtd_func_ptr)(void);

    class FunctionPointerProtection {
    private:
        qtd_func_ptr* function_table;
        qtd_size table_size;
        qtd_uint32 table_key;

    public:
        FunctionPointerProtection(qtd_func_ptr funcs[], qtd_size size, qtd_uint32 key)
            : function_table(funcs),
              table_size(size),
              table_key(key) { }

        QTD_FORCEINLINE void call_function_indirect(qtd_size index) {
            qtd_uint32 fake_idx = static_cast<qtd_uint32>(index ^ table_key);
            qtd_uint32 real_idx = static_cast<qtd_uint32>(fake_idx ^ table_key);

            if (real_idx < table_size) {
                function_table[real_idx]();
            }
        }
    };

    class IntegrityChecker {
    public:
        static QTD_FORCEINLINE qtd_uint32 calculate_checksum(
            const qtd_uint8* data, 
            qtd_size length
        ) {
            qtd_uint32 checksum = 0xDEADBEEF;
            for (qtd_size i = 0; i < length; ++i) {
                checksum = ((checksum << 5) + checksum) ^ data[i];
            }
            return checksum;
        }

        static QTD_FORCEINLINE bool verify_integrity(
            const qtd_uint8* data, 
            qtd_size length,
            qtd_uint32 expected_checksum
        ) {
            return calculate_checksum(data, length) == expected_checksum;
        }
    };
}

#define QTD_ENCRYPT_STRING(str) \
    ([]() { \
        static constexpr const char encrypted_str[] = str; \
        return qtd_crypto::EncryptedConstant< \
            char, \
            sizeof(encrypted_str) / sizeof(char), \
            __COUNTER__ \
        >(encrypted_str, qtd_crypto::make_index_sequence<sizeof(encrypted_str)>()).decrypt(); \
    }())

#define QTD_ENCRYPT_ARRAY(data) \
    qtd_crypto::EncryptedConstant< \
        decltype(data[0]), \
        sizeof(data) / sizeof(data[0]), \
        __COUNTER__ \
    >(data, qtd_crypto::make_index_sequence<sizeof(data)>()).decrypt()

#define QTD_ADD(a, b) qtd_runtime::MBAObfuscation::add_obfuscated(a, b)
#define QTD_SUB(a, b) qtd_runtime::MBAObfuscation::sub_obfuscated(a, b)
#define QTD_MUL(a, b) qtd_runtime::MBAObfuscation::mul_obfuscated(a, b)
#define QTD_XOR(a, b) qtd_runtime::MBAObfuscation::xor_obfuscated(a, b)
#define QTD_AND(a, b) qtd_runtime::MBAObfuscation::and_obfuscated(a, b)
#define QTD_OR(a, b)  qtd_runtime::MBAObfuscation::or_obfuscated(a, b)

#define QTD_ENCRYPT_STR_RUNTIME(str, key) \
    qtd_runtime::StringProtection::encrypt_string(str, strlen(str), key)

#define QTD_DECRYPT_STR_RUNTIME(encrypted, length, key) \
    qtd_runtime::StringProtection::decrypt_string(encrypted, length, key)

#define QTD_SECURE_FREE(ptr) qtd_runtime::StringProtection::secure_free(ptr)

#define QTD_CALC_CHECKSUM(data, length) \
    qtd_runtime::IntegrityChecker::calculate_checksum(data, length)

#define QTD_VERIFY_INTEGRITY(data, length, expected) \
    qtd_runtime::IntegrityChecker::verify_integrity(data, length, expected)

#endif // QUOCTOANDEV_H
