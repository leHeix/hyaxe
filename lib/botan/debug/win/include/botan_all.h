/*
* Botan 3.4.0 Amalgamation
* (C) 1999-2023 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AMALGAMATION_H_
#define BOTAN_AMALGAMATION_H_

#include <algorithm>
#include <array>
#include <chrono>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <iosfwd>
#include <memory>
#include <ostream>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

/**
* @file  build.h
* @brief Build configuration for Botan 3.4.0
*
* Automatically generated from
* 'configure.py --cpu=x86_32 --os=windows --msvc-runtime=MTd --disable-shared-library --amalgamation --minimized-build --enable-modules=bcrypt,system_rng --with-debug-info'
*
* Target
*  - Compiler: cl  /std:c++20 /EHs /GR /MTd /bigobj /Zi /FS /O2 /Oi /Zc:throwingNew
*  - Arch: x86_32
*  - OS: windows
*/

/**
 * @defgroup buildinfo Build Information
 */

/**
 * @ingroup buildinfo
 * @defgroup buildinfo_version Build version information
 * @{
 */

#define BOTAN_VERSION_MAJOR 3
#define BOTAN_VERSION_MINOR 4
#define BOTAN_VERSION_PATCH 0
#define BOTAN_VERSION_DATESTAMP 20240408


#define BOTAN_VERSION_RELEASE_TYPE "release"

#define BOTAN_VERSION_VC_REVISION "git:afd43c536ff96e85d45837caa6f99125483c160a"

#define BOTAN_DISTRIBUTION_INFO "unspecified"

/**
 * @}
 */

/**
 * @ingroup buildinfo
 * @defgroup buildinfo_configuration Build configurations
 * @{
 */

/** How many bits per limb in a BigInt */
#define BOTAN_MP_WORD_BITS 32




#define BOTAN_INSTALL_PREFIX R"(c:\Botan)"
#define BOTAN_INSTALL_HEADER_DIR R"(include/botan-3)"
#define BOTAN_INSTALL_LIB_DIR R"(c:\Botan\lib)"
#define BOTAN_LIB_LINK ""
#define BOTAN_LINK_FLAGS ""


#ifndef BOTAN_DLL
  #define BOTAN_DLL 
#endif

/* Target identification and feature test macros */

#define BOTAN_TARGET_OS_IS_WINDOWS

#define BOTAN_TARGET_OS_HAS_ATOMICS
#define BOTAN_TARGET_OS_HAS_CERTIFICATE_STORE
#define BOTAN_TARGET_OS_HAS_FILESYSTEM
#define BOTAN_TARGET_OS_HAS_RTLGENRANDOM
#define BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY
#define BOTAN_TARGET_OS_HAS_THREAD_LOCAL
#define BOTAN_TARGET_OS_HAS_THREADS
#define BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
#define BOTAN_TARGET_OS_HAS_WIN32
#define BOTAN_TARGET_OS_HAS_WINSOCK2


#define BOTAN_BUILD_COMPILER_IS_MSVC




#define BOTAN_TARGET_ARCH "x86_32"
#define BOTAN_TARGET_ARCH_IS_X86_32
#define BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN
#define BOTAN_TARGET_CPU_IS_X86_FAMILY

#define BOTAN_TARGET_SUPPORTS_AESNI
#define BOTAN_TARGET_SUPPORTS_RDRAND
#define BOTAN_TARGET_SUPPORTS_RDSEED
#define BOTAN_TARGET_SUPPORTS_SHA
#define BOTAN_TARGET_SUPPORTS_SSE2
#define BOTAN_TARGET_SUPPORTS_SSE41
#define BOTAN_TARGET_SUPPORTS_SSE42
#define BOTAN_TARGET_SUPPORTS_SSSE3






/**
 * @}
 */

/**
 * @ingroup buildinfo
 * @defgroup buildinfo_modules Enabled modules and API versions
 * @{
 */

/*
* Module availability definitions
*/
#define BOTAN_HAS_BASE64_CODEC 20131128
#define BOTAN_HAS_BCRYPT 20131128
#define BOTAN_HAS_BLOCK_CIPHER 20131128
#define BOTAN_HAS_BLOWFISH 20180718
#define BOTAN_HAS_CPUID 20170917
#define BOTAN_HAS_DYNAMIC_LOADER 20160310
#define BOTAN_HAS_ENTROPY_SOURCE 20151120
#define BOTAN_HAS_HEX_CODEC 20131128
#define BOTAN_HAS_SYSTEM_RNG 20141202
#define BOTAN_HAS_UTIL_FUNCTIONS 20180903


/**
 * @}
 */

/**
 * @addtogroup buildinfo_configuration
 * @{
 */

/** Local/misc configuration options (if any) follow */


/*
* Things you can edit (but probably shouldn't)
*/

/** How much to allocate for a buffer of no particular size */
#define BOTAN_DEFAULT_BUFFER_SIZE 4096

#if defined(BOTAN_HAS_VALGRIND) || defined(BOTAN_ENABLE_DEBUG_ASSERTS)
   /**
    * @brief Prohibits access to unused memory pages in Botan's memory pool
    *
    * If BOTAN_MEM_POOL_USE_MMU_PROTECTIONS is defined, the Memory_Pool
    * class used for mlock'ed memory will use OS calls to set page
    * permissions so as to prohibit access to pages on the free list, then
    * enable read/write access when the page is set to be used. This will
    * turn (some) use after free bugs into a crash.
    *
    * The additional syscalls have a substantial performance impact, which
    * is why this option is not enabled by default. It is used when built for
    * running in valgrind or debug assertions are enabled.
    */
   #define BOTAN_MEM_POOL_USE_MMU_PROTECTIONS
#endif

/**
* If enabled uses memset via volatile function pointer to zero memory,
* otherwise does a byte at a time write via a volatile pointer.
*/
#define BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO 1

/**
* Normally blinding is performed by choosing a random starting point (plus
* its inverse, of a form appropriate to the algorithm being blinded), and
* then choosing new blinding operands by successive squaring of both
* values. This is much faster than computing a new starting point but
* introduces some possible corelation
*
* To avoid possible leakage problems in long-running processes, the blinder
* periodically reinitializes the sequence. This value specifies how often
* a new sequence should be started.
*/
#define BOTAN_BLINDING_REINIT_INTERVAL 64

/**
* Userspace RNGs like HMAC_DRBG will reseed after a specified number
* of outputs are generated. Set to zero to disable automatic reseeding.
*/
#define BOTAN_RNG_DEFAULT_RESEED_INTERVAL 1024

/** Number of entropy bits polled for reseeding userspace RNGs like HMAC_DRBG */
#define BOTAN_RNG_RESEED_POLL_BITS 256

#define BOTAN_RNG_RESEED_DEFAULT_TIMEOUT std::chrono::milliseconds(50)

/**
* Specifies (in order) the list of entropy sources that will be used
* to seed an in-memory RNG.
*/
#define BOTAN_ENTROPY_DEFAULT_SOURCES \
   { "rdseed", "hwrng", "getentropy", "system_rng", "system_stats" }

/** Multiplier on a block cipher's native parallelism */
#define BOTAN_BLOCK_CIPHER_PAR_MULT 4

/**
 * @}
 */

/* Check for a common build problem */

#if defined(BOTAN_TARGET_ARCH_IS_X86_64) && ((defined(_MSC_VER) && !defined(_WIN64)) || \
                                             (defined(__clang__) && !defined(__x86_64__)) || \
                                             (defined(__GNUG__) && !defined(__x86_64__)))
    #error "Trying to compile Botan configured as x86_64 with non-x86_64 compiler."
#endif

#if defined(BOTAN_TARGET_ARCH_IS_X86_32) && ((defined(_MSC_VER) && defined(_WIN64)) || \
                                             (defined(__clang__) && !defined(__i386__)) || \
                                             (defined(__GNUG__) && !defined(__i386__)))

    #error "Trying to compile Botan configured as x86_32 with non-x86_32 compiler."
#endif

/*
NOTE: Avoid using BOTAN_COMPILER_IS_XXX macros anywhere in this file

This macro is set based on what compiler was used to build the
library, but it is possible that the library is built with one
compiler and then the application is built using another.

For example using BOTAN_COMPILER_IS_CLANG would trigger (incorrectly)
when the application is later compiled using GCC.
*/

/**
* Used to annotate API exports which are public and supported.
* These APIs will not be broken/removed unless strictly required for
* functionality or security, and only in new major versions.
* @param maj The major version this public API was released in
* @param min The minor version this public API was released in
*/
#define BOTAN_PUBLIC_API(maj, min) BOTAN_DLL

/**
* Used to annotate API exports which are public, but are now deprecated
* and which will be removed in a future major release.
*/
#define BOTAN_DEPRECATED_API(msg) BOTAN_DLL BOTAN_DEPRECATED(msg)

/**
* Used to annotate API exports which are public and can be used by
* applications if needed, but which are intentionally not documented,
* and which may change incompatibly in a future major version.
*/
#define BOTAN_UNSTABLE_API BOTAN_DLL

/**
* Used to annotate API exports which are exported but only for the
* purposes of testing. They should not be used by applications and
* may be removed or changed without notice.
*/
#define BOTAN_TEST_API BOTAN_DLL

/**
* Used to annotate API exports which are exported but only for the
* purposes of fuzzing. They should not be used by applications and
* may be removed or changed without notice.
*
* They are only exported if the fuzzers are being built
*/
#if defined(BOTAN_FUZZERS_ARE_BEING_BUILT)
   #define BOTAN_FUZZER_API BOTAN_DLL
#else
   #define BOTAN_FUZZER_API
#endif

/*
* Define BOTAN_COMPILER_HAS_BUILTIN
*/
#if defined(__has_builtin)
   #define BOTAN_COMPILER_HAS_BUILTIN(x) __has_builtin(x)
#else
   #define BOTAN_COMPILER_HAS_BUILTIN(x) 0
#endif

/*
* Define BOTAN_COMPILER_HAS_ATTRIBUTE
*/
#if defined(__has_attribute)
   #define BOTAN_COMPILER_HAS_ATTRIBUTE(x) __has_attribute(x)
   #define BOTAN_COMPILER_ATTRIBUTE(x) __attribute__((x))
#else
   #define BOTAN_COMPILER_HAS_ATTRIBUTE(x) 0
   #define BOTAN_COMPILER_ATTRIBUTE(x) /**/
#endif

/*
* Define BOTAN_FUNC_ISA
*/
#if BOTAN_COMPILER_HAS_ATTRIBUTE(target)
   #define BOTAN_FUNC_ISA(isa) BOTAN_COMPILER_ATTRIBUTE(target(isa))
#else
   #define BOTAN_FUNC_ISA(isa)
#endif

/*
* Define BOTAN_FUNC_ISA_INLINE
*/
#define BOTAN_FUNC_ISA_INLINE(isa) BOTAN_FUNC_ISA(isa) BOTAN_FORCE_INLINE

/*
* Define BOTAN_MALLOC_FN
*/
#if BOTAN_COMPILER_HAS_ATTRIBUTE(malloc)
   #define BOTAN_MALLOC_FN BOTAN_COMPILER_ATTRIBUTE(malloc)
#elif defined(_MSC_VER)
   #define BOTAN_MALLOC_FN __declspec(restrict)
#else
   #define BOTAN_MALLOC_FN
#endif

/*
* Define BOTAN_EARLY_INIT
*/
#if BOTAN_COMPILER_HAS_ATTRIBUTE(init_priority)
   #define BOTAN_EARLY_INIT(prio) BOTAN_COMPILER_ATTRIBUTE(init_priority(prio))
#else
   #define BOTAN_EARLY_INIT(prio) /**/
#endif

/*
* Define BOTAN_DEPRECATED
*/
#if !defined(BOTAN_NO_DEPRECATED_WARNINGS) && !defined(BOTAN_AMALGAMATION_H_) && !defined(BOTAN_IS_BEING_BUILT)

   #define BOTAN_DEPRECATED(msg) [[deprecated(msg)]]

   #if defined(__clang__)
      #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("message \"this header is deprecated\"")
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) _Pragma("message \"this header will be made internal in the future\"")
   #elif defined(_MSC_VER)
      #define BOTAN_DEPRECATED_HEADER(hdr) __pragma(message("this header is deprecated"))
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) __pragma(message("this header will be made internal in the future"))
   #elif defined(__GNUC__)
      #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("GCC warning \"this header is deprecated\"")
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) \
         _Pragma("GCC warning \"this header will be made internal in the future\"")
   #endif

#endif

#if !defined(BOTAN_DEPRECATED)
   #define BOTAN_DEPRECATED(msg)
#endif

#if !defined(BOTAN_DEPRECATED_HEADER)
   #define BOTAN_DEPRECATED_HEADER(hdr)
#endif

#if !defined(BOTAN_FUTURE_INTERNAL_HEADER)
   #define BOTAN_FUTURE_INTERNAL_HEADER(hdr)
#endif

/*
* Define BOTAN_FORCE_INLINE
*/
#if !defined(BOTAN_FORCE_INLINE)

   #if BOTAN_COMPILER_HAS_ATTRIBUTE(always_inline)
      #define BOTAN_FORCE_INLINE inline BOTAN_COMPILER_ATTRIBUTE(always_inline)

   #elif defined(_MSC_VER)
      #define BOTAN_FORCE_INLINE __forceinline

   #else
      #define BOTAN_FORCE_INLINE inline
   #endif

#endif

#if defined(__clang__)
   #define BOTAN_DIAGNOSTIC_PUSH _Pragma("clang diagnostic push")
   #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS \
      _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
   #define BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE
   #define BOTAN_DIAGNOSTIC_POP _Pragma("clang diagnostic pop")
#elif defined(__GNUG__)
   #define BOTAN_DIAGNOSTIC_PUSH _Pragma("GCC diagnostic push")
   #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS \
      _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
   #define BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE
   #define BOTAN_DIAGNOSTIC_POP _Pragma("GCC diagnostic pop")
#elif defined(_MSC_VER)
   #define BOTAN_DIAGNOSTIC_PUSH __pragma(warning(push))
   #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS __pragma(warning(disable : 4996))
   #define BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE __pragma(warning(disable : 4250))
   #define BOTAN_DIAGNOSTIC_POP __pragma(warning(pop))
#else
   #define BOTAN_DIAGNOSTIC_PUSH
   #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS
   #define BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE
   #define BOTAN_DIAGNOSTIC_POP
#endif

namespace Botan {

/**
* Called when an assertion fails
* Throws an Exception object
*/
[[noreturn]] void BOTAN_PUBLIC_API(2, 0)
   assertion_failure(const char* expr_str, const char* assertion_made, const char* func, const char* file, int line);

/**
* Called when an invalid argument is used
* Throws Invalid_Argument
*/
[[noreturn]] void BOTAN_UNSTABLE_API throw_invalid_argument(const char* message, const char* func, const char* file);

#define BOTAN_ARG_CHECK(expr, msg)                               \
   do {                                                          \
      if(!(expr))                                                \
         Botan::throw_invalid_argument(msg, __func__, __FILE__); \
   } while(0)

/**
* Called when an invalid state is encountered
* Throws Invalid_State
*/
[[noreturn]] void BOTAN_UNSTABLE_API throw_invalid_state(const char* message, const char* func, const char* file);

#define BOTAN_STATE_CHECK(expr)                                 \
   do {                                                         \
      if(!(expr))                                               \
         Botan::throw_invalid_state(#expr, __func__, __FILE__); \
   } while(0)

/**
* Make an assertion
*/
#define BOTAN_ASSERT(expr, assertion_made)                                              \
   do {                                                                                 \
      if(!(expr))                                                                       \
         Botan::assertion_failure(#expr, assertion_made, __func__, __FILE__, __LINE__); \
   } while(0)

/**
* Make an assertion
*/
#define BOTAN_ASSERT_NOMSG(expr)                                            \
   do {                                                                     \
      if(!(expr))                                                           \
         Botan::assertion_failure(#expr, "", __func__, __FILE__, __LINE__); \
   } while(0)

/**
* Assert that value1 == value2
*/
#define BOTAN_ASSERT_EQUAL(expr1, expr2, assertion_made)                                               \
   do {                                                                                                \
      if((expr1) != (expr2))                                                                           \
         Botan::assertion_failure(#expr1 " == " #expr2, assertion_made, __func__, __FILE__, __LINE__); \
   } while(0)

/**
* Assert that expr1 (if true) implies expr2 is also true
*/
#define BOTAN_ASSERT_IMPLICATION(expr1, expr2, msg)                                              \
   do {                                                                                          \
      if((expr1) && !(expr2))                                                                    \
         Botan::assertion_failure(#expr1 " implies " #expr2, msg, __func__, __FILE__, __LINE__); \
   } while(0)

/**
* Assert that a pointer is not null
*/
#define BOTAN_ASSERT_NONNULL(ptr)                                                         \
   do {                                                                                   \
      if((ptr) == nullptr)                                                                \
         Botan::assertion_failure(#ptr " is not null", "", __func__, __FILE__, __LINE__); \
   } while(0)

#if defined(BOTAN_ENABLE_DEBUG_ASSERTS)

   #define BOTAN_DEBUG_ASSERT(expr) BOTAN_ASSERT_NOMSG(expr)

#else

   #define BOTAN_DEBUG_ASSERT(expr) \
      do {                          \
      } while(0)

#endif

/**
* Mark variable as unused.
*
* Takes any number of arguments and marks all as unused, for instance
* BOTAN_UNUSED(a); or BOTAN_UNUSED(x, y, z);
*/
template <typename T>
constexpr void ignore_param(T&&) {}

template <typename... T>
constexpr void ignore_params(T&&... args) {
   (ignore_param(args), ...);
}

#define BOTAN_UNUSED Botan::ignore_params

/*
* Define Botan::assert_unreachable and BOTAN_ASSERT_UNREACHABLE
*
* This is intended to be used in the same situations as `std::unreachable()`;
* a codepath that (should not) be reachable but where the compiler cannot
* tell that it is unreachable.
*
* Unlike `std::unreachable()`, or equivalent compiler builtins like GCC's
* `__builtin_unreachable`, this function is not UB. By default it will
* throw an exception. If `BOTAN_TERMINATE_ON_ASSERTS` is defined, it will
* instead print a message to stderr and abort.
*
* Due to this difference, and the fact that it is not inlined, calling
* this is significantly more costly than using `std::unreachable`.
*/
[[noreturn]] void BOTAN_UNSTABLE_API assert_unreachable(const char* file, int line);

#define BOTAN_ASSERT_UNREACHABLE() Botan::assert_unreachable(__FILE__, __LINE__)

}  // namespace Botan

namespace Botan {

/**
* @mainpage Botan Crypto Library API Reference
*
* <dl>
* <dt>Abstract Base Classes<dd>
*        BlockCipher, HashFunction, KDF, MessageAuthenticationCode, RandomNumberGenerator,
*        StreamCipher, SymmetricAlgorithm, AEAD_Mode, Cipher_Mode, XOF
* <dt>Public Key Interface Classes<dd>
*        PK_Key_Agreement, PK_Signer, PK_Verifier, PK_Encryptor, PK_Decryptor, PK_KEM_Encryptor, PK_KEM_Decryptor
* <dt>Authenticated Encryption Modes<dd>
*        @ref CCM_Mode "CCM", @ref ChaCha20Poly1305_Mode "ChaCha20Poly1305", @ref EAX_Mode "EAX",
*        @ref GCM_Mode "GCM", @ref OCB_Mode "OCB", @ref SIV_Mode "SIV"
* <dt>Block Ciphers<dd>
*        @ref aria.h "ARIA", @ref aes.h "AES", @ref Blowfish, @ref camellia.h "Camellia", @ref Cascade_Cipher "Cascade",
*        @ref CAST_128 "CAST-128", @ref CAST_128 DES, @ref TripleDES "3DES",
*        @ref GOST_28147_89 "GOST 28147-89", IDEA, Kuznyechik, Lion, Noekeon, SEED, Serpent, SHACAL2, SM4,
*        @ref Threefish_512 "Threefish", Twofish
* <dt>Stream Ciphers<dd>
*        ChaCha, @ref CTR_BE "CTR", OFB, RC4, Salsa20
* <dt>Hash Functions<dd>
*        BLAKE2b, @ref GOST_34_11 "GOST 34.11", @ref Keccak_1600 "Keccak", MD4, MD5, @ref RIPEMD_160 "RIPEMD-160",
*        @ref SHA_1 "SHA-1", @ref SHA_224 "SHA-224", @ref SHA_256 "SHA-256", @ref SHA_384 "SHA-384",
*        @ref SHA_512 "SHA-512", @ref Skein_512 "Skein-512", SM3, Streebog, Whirlpool
* <dt>Non-Cryptographic Checksums<dd>
*        Adler32, CRC24, CRC32
* <dt>Message Authentication Codes<dd>
*        @ref BLAKE2bMAC "BLAKE2b", CMAC, HMAC, KMAC, Poly1305, SipHash, ANSI_X919_MAC
* <dt>Random Number Generators<dd>
*        AutoSeeded_RNG, HMAC_DRBG, Processor_RNG, System_RNG
* <dt>Key Derivation<dd>
*        HKDF, @ref KDF1 "KDF1 (IEEE 1363)", @ref KDF1_18033 "KDF1 (ISO 18033-2)", @ref KDF2 "KDF2 (IEEE 1363)",
*        @ref sp800_108.h "SP800-108", @ref SP800_56C "SP800-56C", @ref PKCS5_PBKDF2 "PBKDF2 (PKCS#5)"
* <dt>Password Hashing<dd>
*        @ref argon2.h "Argon2", @ref scrypt.h "scrypt", @ref bcrypt.h "bcrypt", @ref passhash9.h "passhash9"
* <dt>Public Key Cryptosystems<dd>
*        @ref dlies.h "DLIES", @ref ecies.h "ECIES", @ref elgamal.h "ElGamal",
*        @ref rsa.h "RSA", @ref mceliece.h "McEliece", @ref sm2.h "SM2"
* <dt>Key Encapsulation Mechanisms<dd>
*        @ref frodokem.h "FrodoKEM", @ref kyber.h "Kyber", @ref rsa.h "RSA"
* <dt>Public Key Signature Schemes<dd>
*        @ref dsa.h "DSA", @ref dilithium.h "Dilithium", @ref ecdsa.h "ECDSA", @ref ecgdsa.h "ECGDSA",
*        @ref eckcdsa.h "ECKCDSA", @ref gost_3410.h "GOST 34.10-2001", @ref sm2.h "SM2", @ref sphincsplus.h "SPHINCS+",
*        @ref xmss.h "XMSS"
* <dt>Key Agreement<dd>
*        @ref dh.h "DH", @ref ecdh.h "ECDH"
* <dt>Compression<dd>
*        @ref bzip2.h "bzip2", @ref lzma.h "lzma", @ref zlib.h "zlib"
* <dt>TLS<dd>
*        TLS::Client, TLS::Server, TLS::Policy, TLS::Protocol_Version, TLS::Callbacks, TLS::Ciphersuite,
*        TLS::Session, TLS::Session_Summary, TLS::Session_Manager, Credentials_Manager
* <dt>X.509<dd>
*        X509_Certificate, X509_CRL, X509_CA, Certificate_Extension, PKCS10_Request, X509_Cert_Options,
*        Certificate_Store, Certificate_Store_In_SQL, Certificate_Store_In_SQLite
* <dt>eXtendable Output Functions<dd>
*        @ref SHAKE_XOF "SHAKE"
* </dl>
*/

using std::int32_t;
using std::int64_t;
using std::size_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::uint8_t;

#if !defined(BOTAN_IS_BEING_BUILT)
/*
* These typedefs are no longer used within the library headers
* or code. They are kept only for compatability with software
* written against older versions.
*/
using byte = std::uint8_t;
using u16bit = std::uint16_t;
using u32bit = std::uint32_t;
using u64bit = std::uint64_t;
using s32bit = std::int32_t;
#endif

#if(BOTAN_MP_WORD_BITS == 32)
typedef uint32_t word;
#elif(BOTAN_MP_WORD_BITS == 64)
typedef uint64_t word;
#else
   #error BOTAN_MP_WORD_BITS must be 32 or 64
#endif

#if defined(__SIZEOF_INT128__) && defined(BOTAN_TARGET_CPU_HAS_NATIVE_64BIT)
   #define BOTAN_TARGET_HAS_NATIVE_UINT128

// GCC complains if this isn't marked with __extension__
__extension__ typedef unsigned __int128 uint128_t;
#endif

/*
* Should this assert fail on your system please contact the developers
* for assistance in porting.
*/
static_assert(sizeof(std::size_t) == 8 || sizeof(std::size_t) == 4, "This platform has an unexpected size for size_t");

}  // namespace Botan

namespace Botan {

/**
* Allocate a memory buffer by some method. This should only be used for
* primitive types (uint8_t, uint32_t, etc).
*
* @param elems the number of elements
* @param elem_size the size of each element
* @return pointer to allocated and zeroed memory, or throw std::bad_alloc on failure
*/
BOTAN_PUBLIC_API(2, 3) BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size);

/**
* Free a pointer returned by allocate_memory
* @param p the pointer returned by allocate_memory
* @param elems the number of elements, as passed to allocate_memory
* @param elem_size the size of each element, as passed to allocate_memory
*/
BOTAN_PUBLIC_API(2, 3) void deallocate_memory(void* p, size_t elems, size_t elem_size);

/**
* Ensure the allocator is initialized
*/
void BOTAN_UNSTABLE_API initialize_allocator();

class Allocator_Initializer final {
   public:
      Allocator_Initializer() { initialize_allocator(); }
};

}  // namespace Botan

namespace Botan {

template <typename T>
#if !defined(_ITERATOR_DEBUG_LEVEL) || _ITERATOR_DEBUG_LEVEL == 0
/*
  * Assert exists to prevent someone from doing something that will
  * probably crash anyway (like secure_vector<non_POD_t> where ~non_POD_t
  * deletes a member pointer which was zeroed before it ran).
  * MSVC in debug mode uses non-integral proxy types in container types
  * like std::vector, thus we disable the check there.
 */
   requires std::is_integral<T>::value
#endif
class secure_allocator {

   public:
      typedef T value_type;
      typedef std::size_t size_type;

      secure_allocator() noexcept = default;
      secure_allocator(const secure_allocator&) noexcept = default;
      secure_allocator& operator=(const secure_allocator&) noexcept = default;
      ~secure_allocator() noexcept = default;

      template <typename U>
      secure_allocator(const secure_allocator<U>&) noexcept {}

      T* allocate(std::size_t n) { return static_cast<T*>(allocate_memory(n, sizeof(T))); }

      void deallocate(T* p, std::size_t n) { deallocate_memory(p, n, sizeof(T)); }
};

template <typename T, typename U>
inline bool operator==(const secure_allocator<T>&, const secure_allocator<U>&) {
   return true;
}

template <typename T, typename U>
inline bool operator!=(const secure_allocator<T>&, const secure_allocator<U>&) {
   return false;
}

template <typename T>
using secure_vector = std::vector<T, secure_allocator<T>>;
template <typename T>
using secure_deque = std::deque<T, secure_allocator<T>>;

// For better compatibility with 1.10 API
template <typename T>
using SecureVector = secure_vector<T>;

template <typename T>
secure_vector<T> lock(const std::vector<T>& in) {
   return secure_vector<T>(in.begin(), in.end());
}

template <typename T>
std::vector<T> unlock(const secure_vector<T>& in) {
   return std::vector<T>(in.begin(), in.end());
}

template <typename T, typename Alloc, typename Alloc2>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, const std::vector<T, Alloc2>& in) {
   out.insert(out.end(), in.begin(), in.end());
   return out;
}

template <typename T, typename Alloc>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, T in) {
   out.push_back(in);
   return out;
}

template <typename T, typename Alloc, typename L>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, const std::pair<const T*, L>& in) {
   out.insert(out.end(), in.first, in.first + in.second);
   return out;
}

template <typename T, typename Alloc, typename L>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, const std::pair<T*, L>& in) {
   out.insert(out.end(), in.first, in.first + in.second);
   return out;
}

/**
* Zeroise the values; length remains unchanged
* @param vec the vector to zeroise
*/
template <typename T, typename Alloc>
void zeroise(std::vector<T, Alloc>& vec) {
   std::fill(vec.begin(), vec.end(), static_cast<T>(0));
}

/**
* Zeroise the values then free the memory
* @param vec the vector to zeroise and free
*/
template <typename T, typename Alloc>
void zap(std::vector<T, Alloc>& vec) {
   zeroise(vec);
   vec.clear();
   vec.shrink_to_fit();
}

}  // namespace Botan

namespace Botan {

/**
* Perform base64 encoding
* @param output an array of at least base64_encode_max_output bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*        bytes of input were actually consumed. If less than
*        input_length, then the range input[consumed:length]
*        should be passed in later along with more input.
* @param final_inputs true iff this is the last input, in which case
         padding chars will be applied if needed
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2, 0)
   base64_encode(char output[], const uint8_t input[], size_t input_length, size_t& input_consumed, bool final_inputs);

/**
* Perform base64 encoding
* @param input some input
* @param input_length length of input in bytes
* @return base64adecimal representation of input
*/
std::string BOTAN_PUBLIC_API(2, 0) base64_encode(const uint8_t input[], size_t input_length);

/**
* Perform base64 encoding
* @param input some input
* @return base64adecimal representation of input
*/
inline std::string base64_encode(std::span<const uint8_t> input) {
   return base64_encode(input.data(), input.size());
}

/**
* Perform base64 decoding
* @param output an array of at least base64_decode_max_output bytes
* @param input some base64 input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*        bytes of input were actually consumed. If less than
*        input_length, then the range input[consumed:length]
*        should be passed in later along with more input.
* @param final_inputs true iff this is the last input, in which case
         padding is allowed
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2, 0) base64_decode(uint8_t output[],
                                            const char input[],
                                            size_t input_length,
                                            size_t& input_consumed,
                                            bool final_inputs,
                                            bool ignore_ws = true);

/**
* Perform base64 decoding
* @param output an array of at least base64_decode_max_output bytes
* @param input some base64 input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2, 0)
   base64_decode(uint8_t output[], const char input[], size_t input_length, bool ignore_ws = true);

/**
* Perform base64 decoding
* @param output an array of at least base64_decode_max_output bytes
* @param input some base64 input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(3, 0) base64_decode(uint8_t output[], std::string_view input, bool ignore_ws = true);

/**
* Perform base64 decoding
* @param output a contiguous byte buffer of at least base64_decode_max_output bytes
* @param input some base64 input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(3, 0) base64_decode(std::span<uint8_t> output, std::string_view input, bool ignore_ws = true);

/**
* Perform base64 decoding
* @param input some base64 input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded base64 output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2, 0)
   base64_decode(const char input[], size_t input_length, bool ignore_ws = true);

/**
* Perform base64 decoding
* @param input some base64 input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded base64 output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(3, 0) base64_decode(std::string_view input, bool ignore_ws = true);

/**
* Calculate the size of output buffer for base64_encode
* @param input_length the length of input in bytes
* @return the size of output buffer in bytes
*/
size_t BOTAN_PUBLIC_API(2, 1) base64_encode_max_output(size_t input_length);

/**
* Calculate the size of output buffer for base64_decode
* @param input_length the length of input in bytes
* @return the size of output buffer in bytes
*/
size_t BOTAN_PUBLIC_API(2, 1) base64_decode_max_output(size_t input_length);

}  // namespace Botan

namespace Botan {

class RandomNumberGenerator;

/**
* Create a password hash using Bcrypt
*
* @warning The password is truncated at at most 72 characters; characters after
*          that do not have any effect on the resulting hash. To support longer
*          passwords, consider pre-hashing the password, for example by using
*          the hex encoding of SHA-256 of the password as the input to bcrypt.
*
* @param password the password.
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
* @param version which version to emit (may be 'a', 'b', or 'y' all of which
*        have identical behavior in this implementation).
*
* @see https://www.usenix.org/events/usenix99/provos/provos_html/
*/
std::string BOTAN_PUBLIC_API(2, 0) generate_bcrypt(std::string_view password,
                                                   RandomNumberGenerator& rng,
                                                   uint16_t work_factor = 12,
                                                   char version = 'a');

/**
* Check a previously created password hash
* @param password the password to check against
* @param hash the stored hash to check against
*/
bool BOTAN_PUBLIC_API(2, 0) check_bcrypt(std::string_view password, std::string_view hash);

}  // namespace Botan


namespace Botan {

template <typename T, typename Tag, typename... Capabilities>
class Strong;

template <typename... Ts>
struct is_strong_type : std::false_type {};

template <typename... Ts>
struct is_strong_type<Strong<Ts...>> : std::true_type {};

template <typename... Ts>
constexpr bool is_strong_type_v = is_strong_type<std::remove_const_t<Ts>...>::value;

template <typename T0, typename... Ts>
struct all_same {
      static constexpr bool value = (std::is_same_v<T0, Ts> && ...);
};

template <typename... Ts>
static constexpr bool all_same_v = all_same<Ts...>::value;

namespace ranges {

/**
 * Models a std::ranges::contiguous_range that (optionally) restricts its
 * value_type to ValueT. In other words: a stretch of contiguous memory of
 * a certain type (optional ValueT).
 */
template <typename T, typename ValueT = std::ranges::range_value_t<T>>
concept contiguous_range = std::ranges::contiguous_range<T> && std::same_as<ValueT, std::ranges::range_value_t<T>>;

/**
 * Models a std::ranges::contiguous_range that satisfies
 * std::ranges::output_range with an arbitrary value_type. In other words: a
 * stretch of contiguous memory of a certain type (optional ValueT) that can be
 * written to.
 */
template <typename T, typename ValueT = std::ranges::range_value_t<T>>
concept contiguous_output_range = contiguous_range<T, ValueT> && std::ranges::output_range<T, ValueT>;

/**
 * Models a range that can be turned into a std::span<>. Typically, this is some
 * form of ranges::contiguous_range.
 */
template <typename T>
concept spanable_range = std::constructible_from<std::span<const std::ranges::range_value_t<T>>, T>;

/**
 * Models a range that can be turned into a std::span<> with a static extent.
 * Typically, this is a std::array or a std::span derived from an array.
 */
// clang-format off
template <typename T>
concept statically_spanable_range = spanable_range<T> &&
                                    decltype(std::span{std::declval<T&>()})::extent != std::dynamic_extent;

// clang-format on

/**
 * Find the length in bytes of a given contiguous range @p r.
 */
inline constexpr size_t size_bytes(spanable_range auto&& r) {
   return std::span{r}.size_bytes();
}

/**
 * Check that a given range @p r has a certain statically-known byte length. If
 * the range's extent is known at compile time, this is a static check,
 * otherwise a runtime argument check will be added.
 *
 * @throws Invalid_Argument  if range @p r has a dynamic extent and does not
 *                           feature the expected byte length.
 */
template <size_t expected, spanable_range R>
inline constexpr void assert_exact_byte_length(R&& r) {
   const std::span s{r};
   if constexpr(statically_spanable_range<R>) {
      static_assert(s.size_bytes() == expected, "memory region does not have expected byte lengths");
   } else {
      BOTAN_ASSERT(s.size_bytes() == expected, "memory region does not have expected byte lengths");
   }
}

/**
 * Check that a list of ranges (in @p r0 and @p rs) all have the same byte
 * lengths. If the first range's extent is known at compile time, this will be a
 * static check for all other ranges whose extents are known at compile time,
 * otherwise a runtime argument check will be added.
 *
 * @throws Invalid_Argument  if any range has a dynamic extent and not all
 *                           ranges feature the same byte length.
 */
template <spanable_range R0, spanable_range... Rs>
inline constexpr void assert_equal_byte_lengths(R0&& r0, Rs&&... rs)
   requires(sizeof...(Rs) > 0)
{
   const std::span s0{r0};

   if constexpr(statically_spanable_range<R0>) {
      constexpr size_t expected_size = s0.size_bytes();
      (assert_exact_byte_length<expected_size>(rs), ...);
   } else {
      const size_t expected_size = s0.size_bytes();
      BOTAN_ARG_CHECK(((std::span<const std::ranges::range_value_t<Rs>>{rs}.size_bytes() == expected_size) && ...),
                      "memory regions don't have equal lengths");
   }
}

}  // namespace ranges

namespace concepts {

// TODO: C++20 provides concepts like std::ranges::range or ::sized_range
//       but at the time of this writing clang had not caught up on all
//       platforms. E.g. clang 14 on Xcode does not support ranges properly.

template <typename IterT, typename ContainerT>
concept container_iterator =
   std::same_as<IterT, typename ContainerT::iterator> || std::same_as<IterT, typename ContainerT::const_iterator>;

template <typename PtrT, typename ContainerT>
concept container_pointer =
   std::same_as<PtrT, typename ContainerT::pointer> || std::same_as<PtrT, typename ContainerT::const_pointer>;

template <typename T>
concept container = requires(T a) {
                       { a.begin() } -> container_iterator<T>;
                       { a.end() } -> container_iterator<T>;
                       { a.cbegin() } -> container_iterator<T>;
                       { a.cend() } -> container_iterator<T>;
                       { a.size() } -> std::same_as<typename T::size_type>;
                       typename T::value_type;
                    };

template <typename T>
concept contiguous_container = container<T> && requires(T a) {
                                                  { a.data() } -> container_pointer<T>;
                                               };

template <typename T>
concept has_empty = requires(T a) {
                       { a.empty() } -> std::same_as<bool>;
                    };

template <typename T>
concept resizable_container = container<T> && requires(T& c, typename T::size_type s) {
                                                 T(s);
                                                 c.resize(s);
                                              };

template <typename T>
concept resizable_byte_buffer =
   contiguous_container<T> && resizable_container<T> && std::same_as<typename T::value_type, uint8_t>;

template <typename T>
concept streamable = requires(std::ostream& os, T a) { os << a; };

template <class T>
concept strong_type = is_strong_type_v<T>;

template <class T>
concept contiguous_strong_type = strong_type<T> && contiguous_container<T>;

template <class T>
concept unsigned_integral_strong_type = strong_type<T> && std::unsigned_integral<typename T::wrapped_type>;

}  // namespace concepts

}  // namespace Botan

/*
The header mem_ops.h previously included the contents of allocator.h

Library code should always include allocator.h to see these
declarations; however when we are not building the library continue to
include the header here to avoid breaking application code.
*/
#if !defined(BOTAN_IS_BEING_BUILT)
#endif

namespace Botan {

/**
* Scrub memory contents in a way that a compiler should not elide,
* using some system specific technique. Note that this function might
* not zero the memory (for example, in some hypothetical
* implementation it might combine the memory contents with the output
* of a system PRNG), but if you can detect any difference in behavior
* at runtime then the clearing is side-effecting and you can just
* use `clear_mem`.
*
* Use this function to scrub memory just before deallocating it, or on
* a stack buffer before returning from the function.
*
* @param ptr a pointer to memory to scrub
* @param n the number of bytes pointed to by ptr
*/
BOTAN_PUBLIC_API(2, 0) void secure_scrub_memory(void* ptr, size_t n);

/**
* Scrub memory contents in a way that a compiler should not elide,
* using some system specific technique. Note that this function might
* not zero the memory.
*
* @param data  the data region to be scrubbed
*/
void secure_scrub_memory(ranges::contiguous_output_range auto&& data) {
   secure_scrub_memory(std::ranges::data(data), ranges::size_bytes(data));
}

#if !defined(BOTAN_IS_BEGIN_BUILT)

/**
* Memory comparison, input insensitive
* @param x a pointer to an array
* @param y a pointer to another array
* @param len the number of Ts in x and y
* @return 0xFF iff x[i] == y[i] forall i in [0...n) or 0x00 otherwise
*/
BOTAN_DEPRECATED("This function is deprecated, use constant_time_compare()")
BOTAN_PUBLIC_API(2, 9) uint8_t ct_compare_u8(const uint8_t x[], const uint8_t y[], size_t len);

#endif

/**
 * Memory comparison, input insensitive
 * @param x a range of bytes
 * @param y another range of bytes
 * @return true iff x and y have equal lengths and x[i] == y[i] forall i in [0...n)
 */
BOTAN_PUBLIC_API(3, 3) bool constant_time_compare(std::span<const uint8_t> x, std::span<const uint8_t> y);

/**
* Memory comparison, input insensitive
* @param x a pointer to an array
* @param y a pointer to another array
* @param len the number of Ts in x and y
* @return true iff x[i] == y[i] forall i in [0...n)
*/
inline bool constant_time_compare(const uint8_t x[], const uint8_t y[], size_t len) {
   // simply assumes that *x and *y point to len allocated bytes at least
   return constant_time_compare({x, len}, {y, len});
}

/**
* Zero out some bytes. Warning: use secure_scrub_memory instead if the
* memory is about to be freed or otherwise the compiler thinks it can
* elide the writes.
*
* @param ptr a pointer to memory to zero
* @param bytes the number of bytes to zero in ptr
*/
inline constexpr void clear_bytes(void* ptr, size_t bytes) {
   if(bytes > 0) {
      std::memset(ptr, 0, bytes);
   }
}

/**
* Zero memory before use. This simply calls memset and should not be
* used in cases where the compiler cannot see the call as a
* side-effecting operation (for example, if calling clear_mem before
* deallocating memory, the compiler would be allowed to omit the call
* to memset entirely under the as-if rule.)
*
* @param ptr a pointer to an array of Ts to zero
* @param n the number of Ts pointed to by ptr
*/
template <typename T>
inline constexpr void clear_mem(T* ptr, size_t n) {
   clear_bytes(ptr, sizeof(T) * n);
}

/**
* Zero memory before use. This simply calls memset and should not be
* used in cases where the compiler cannot see the call as a
* side-effecting operation.
*
* @param mem a contiguous range of Ts to zero
*/
template <ranges::contiguous_output_range R>
inline constexpr void clear_mem(R&& mem)
   requires std::is_trivially_copyable_v<std::ranges::range_value_t<R>>
{
   clear_bytes(std::ranges::data(mem), ranges::size_bytes(mem));
}

/**
* Copy memory
* @param out the destination array
* @param in the source array
* @param n the number of elements of in/out
*/
template <typename T>
   requires std::is_trivial<typename std::decay<T>::type>::value
inline constexpr void copy_mem(T* out, const T* in, size_t n) {
   BOTAN_ASSERT_IMPLICATION(n > 0, in != nullptr && out != nullptr, "If n > 0 then args are not null");

   if(in != nullptr && out != nullptr && n > 0) {
      std::memmove(out, in, sizeof(T) * n);
   }
}

/**
* Copy memory
* @param out the destination array
* @param in the source array
*/
template <ranges::contiguous_output_range OutR, ranges::contiguous_range InR>
   requires std::is_same_v<std::ranges::range_value_t<OutR>, std::ranges::range_value_t<InR>> &&
            std::is_trivially_copyable_v<std::ranges::range_value_t<InR>>
inline constexpr void copy_mem(OutR&& out, InR&& in) {
   ranges::assert_equal_byte_lengths(out, in);
   if(std::is_constant_evaluated()) {
      std::copy(std::ranges::begin(in), std::ranges::end(in), std::ranges::begin(out));
   } else if(ranges::size_bytes(out) > 0) {
      std::memmove(std::ranges::data(out), std::ranges::data(in), ranges::size_bytes(out));
   }
}

/**
 * Copy a range of a trivially copyable type into another range of trivially
 * copyable type of matching byte length.
 */
template <ranges::contiguous_output_range ToR, ranges::contiguous_range FromR>
   requires std::is_trivially_copyable_v<std::ranges::range_value_t<FromR>> &&
            std::is_trivially_copyable_v<std::ranges::range_value_t<ToR>>
inline constexpr void typecast_copy(ToR&& out, FromR&& in) {
   ranges::assert_equal_byte_lengths(out, in);
   std::memcpy(std::ranges::data(out), std::ranges::data(in), ranges::size_bytes(out));
}

/**
 * Copy a range of trivially copyable type into an instance of trivially
 * copyable type with matching length.
 */
template <typename ToT, ranges::contiguous_range FromR>
   requires std::is_trivially_copyable_v<std::ranges::range_value_t<FromR>> && std::is_trivially_copyable_v<ToT> &&
            (!std::ranges::range<ToT>)
inline constexpr void typecast_copy(ToT& out, FromR&& in) noexcept {
   typecast_copy(std::span<ToT, 1>(&out, 1), in);
}

/**
 * Copy an instance of trivially copyable type into a range of trivially
 * copyable type with matching length.
 */
template <ranges::contiguous_output_range ToR, typename FromT>
   requires std::is_trivially_copyable_v<FromT> &&
            (!std::ranges::range<FromT>) && std::is_trivially_copyable_v<std::ranges::range_value_t<ToR>>
inline constexpr void typecast_copy(ToR&& out, const FromT& in) {
   typecast_copy(out, std::span<const FromT, 1>(&in, 1));
}

/**
 * Create a trivial type by bit-casting a range of trivially copyable type with
 * matching length into it.
 */
template <typename ToT, ranges::contiguous_range FromR>
   requires std::is_default_constructible_v<ToT> && std::is_trivially_copyable_v<ToT> &&
            std::is_trivially_copyable_v<std::ranges::range_value_t<FromR>>
inline constexpr ToT typecast_copy(FromR&& src) noexcept {
   ToT dst;
   typecast_copy(dst, src);
   return dst;
}

// TODO: deprecate and replace
template <typename T>
inline constexpr void typecast_copy(uint8_t out[], T in[], size_t N)
   requires std::is_trivially_copyable<T>::value
{
   // asserts that *in and *out point to the correct amount of memory
   typecast_copy(std::span<uint8_t>(out, sizeof(T) * N), std::span<const T>(in, N));
}

// TODO: deprecate and replace
template <typename T>
inline constexpr void typecast_copy(T out[], const uint8_t in[], size_t N)
   requires std::is_trivial<T>::value
{
   // asserts that *in and *out point to the correct amount of memory
   typecast_copy(std::span<T>(out, N), std::span<const uint8_t>(in, N * sizeof(T)));
}

// TODO: deprecate and replace
template <typename T>
inline constexpr void typecast_copy(uint8_t out[], const T& in) {
   // asserts that *out points to the correct amount of memory
   typecast_copy(std::span<uint8_t, sizeof(T)>(out, sizeof(T)), in);
}

// TODO: deprecate and replace
template <typename T>
   requires std::is_trivial<typename std::decay<T>::type>::value
inline constexpr void typecast_copy(T& out, const uint8_t in[]) {
   // asserts that *in points to the correct amount of memory
   typecast_copy(out, std::span<const uint8_t, sizeof(T)>(in, sizeof(T)));
}

// TODO: deprecate and replace
template <typename To>
   requires std::is_trivial<To>::value
inline constexpr To typecast_copy(const uint8_t src[]) noexcept {
   // asserts that *src points to the correct amount of memory
   return typecast_copy<To>(std::span<const uint8_t, sizeof(To)>(src, sizeof(To)));
}

#if !defined(BOTAN_IS_BEGIN_BUILT)
/**
* Set memory to a fixed value
* @param ptr a pointer to an array of bytes
* @param n the number of Ts pointed to by ptr
* @param val the value to set each byte to
*/
BOTAN_DEPRECATED("This function is deprecated")

inline constexpr void set_mem(uint8_t* ptr, size_t n, uint8_t val) {
   if(n > 0) {
      std::memset(ptr, val, n);
   }
}
#endif

inline const uint8_t* cast_char_ptr_to_uint8(const char* s) {
   return reinterpret_cast<const uint8_t*>(s);
}

inline const char* cast_uint8_ptr_to_char(const uint8_t* b) {
   return reinterpret_cast<const char*>(b);
}

inline uint8_t* cast_char_ptr_to_uint8(char* s) {
   return reinterpret_cast<uint8_t*>(s);
}

inline char* cast_uint8_ptr_to_char(uint8_t* b) {
   return reinterpret_cast<char*>(b);
}

#if !defined(BOTAN_IS_BEING_BUILT)
/**
* Memory comparison, input insensitive
* @param p1 a pointer to an array
* @param p2 a pointer to another array
* @param n the number of Ts in p1 and p2
* @return true iff p1[i] == p2[i] forall i in [0...n)
*/
template <typename T>
BOTAN_DEPRECATED("This function is deprecated")
inline bool same_mem(const T* p1, const T* p2, size_t n) {
   volatile T difference = 0;

   for(size_t i = 0; i != n; ++i) {
      difference = difference | (p1[i] ^ p2[i]);
   }

   return difference == 0;
}
#endif

#if !defined(BOTAN_IS_BEING_BUILT)

template <typename T, typename Alloc>
BOTAN_DEPRECATED("The buffer_insert functions are deprecated")
size_t buffer_insert(std::vector<T, Alloc>& buf, size_t buf_offset, const T input[], size_t input_length) {
   BOTAN_ASSERT_NOMSG(buf_offset <= buf.size());
   const size_t to_copy = std::min(input_length, buf.size() - buf_offset);
   if(to_copy > 0) {
      copy_mem(&buf[buf_offset], input, to_copy);
   }
   return to_copy;
}

template <typename T, typename Alloc, typename Alloc2>
BOTAN_DEPRECATED("The buffer_insert functions are deprecated")
size_t buffer_insert(std::vector<T, Alloc>& buf, size_t buf_offset, const std::vector<T, Alloc2>& input) {
   BOTAN_ASSERT_NOMSG(buf_offset <= buf.size());
   const size_t to_copy = std::min(input.size(), buf.size() - buf_offset);
   if(to_copy > 0) {
      copy_mem(&buf[buf_offset], input.data(), to_copy);
   }
   return to_copy;
}

#endif

/**
* XOR arrays. Postcondition out[i] = in[i] ^ out[i] forall i = 0...length
* @param out the input/output range
* @param in the read-only input range
*/
inline constexpr void xor_buf(ranges::contiguous_output_range<uint8_t> auto&& out,
                              ranges::contiguous_range<uint8_t> auto&& in) {
   ranges::assert_equal_byte_lengths(out, in);

   std::span o{out};
   std::span i{in};

   for(; o.size_bytes() >= 32; o = o.subspan(32), i = i.subspan(32)) {
      auto x = typecast_copy<std::array<uint64_t, 4>>(o.template first<32>());
      const auto y = typecast_copy<std::array<uint64_t, 4>>(i.template first<32>());

      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];

      typecast_copy(o.template first<32>(), x);
   }

   for(size_t off = 0; off != o.size_bytes(); ++off) {
      o[off] ^= i[off];
   }
}

/**
* XOR arrays. Postcondition out[i] = in1[i] ^ in2[i] forall i = 0...length
* @param out the output range
* @param in1 the first input range
* @param in2 the second input range
*/
inline constexpr void xor_buf(ranges::contiguous_output_range<uint8_t> auto&& out,
                              ranges::contiguous_range<uint8_t> auto&& in1,
                              ranges::contiguous_range<uint8_t> auto&& in2) {
   ranges::assert_equal_byte_lengths(out, in1, in2);

   std::span o{out};
   std::span i1{in1};
   std::span i2{in2};

   for(; o.size_bytes() >= 32; o = o.subspan(32), i1 = i1.subspan(32), i2 = i2.subspan(32)) {
      auto x = typecast_copy<std::array<uint64_t, 4>>(i1.template first<32>());
      const auto y = typecast_copy<std::array<uint64_t, 4>>(i2.template first<32>());

      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];

      typecast_copy(o.template first<32>(), x);
   }

   for(size_t off = 0; off != o.size_bytes(); ++off) {
      o[off] = i1[off] ^ i2[off];
   }
}

/**
* XOR arrays. Postcondition out[i] = in[i] ^ out[i] forall i = 0...length
* @param out the input/output buffer
* @param in the read-only input buffer
* @param length the length of the buffers
*/
inline void xor_buf(uint8_t out[], const uint8_t in[], size_t length) {
   // simply assumes that *out and *in point to "length" allocated bytes at least
   xor_buf(std::span{out, length}, std::span{in, length});
}

/**
* XOR arrays. Postcondition out[i] = in[i] ^ in2[i] forall i = 0...length
* @param out the output buffer
* @param in the first input buffer
* @param in2 the second input buffer
* @param length the length of the three buffers
*/
inline void xor_buf(uint8_t out[], const uint8_t in[], const uint8_t in2[], size_t length) {
   // simply assumes that *out, *in, and *in2 point to "length" allocated bytes at least
   xor_buf(std::span{out, length}, std::span{in, length}, std::span{in2, length});
}

// TODO: deprecate and replace, use .subspan()
inline void xor_buf(std::span<uint8_t> out, std::span<const uint8_t> in, size_t n) {
   BOTAN_ARG_CHECK(out.size() >= n, "output span is too small");
   BOTAN_ARG_CHECK(in.size() >= n, "input span is too small");
   xor_buf(out.first(n), in.first(n));
}

// TODO: deprecate and replace, use .subspan()
template <typename Alloc>
void xor_buf(std::vector<uint8_t, Alloc>& out, const uint8_t* in, size_t n) {
   BOTAN_ARG_CHECK(out.size() >= n, "output vector is too small");
   // simply assumes that *in points to "n" allocated bytes at least
   xor_buf(std::span{out}.first(n), std::span{in, n});
}

// TODO: deprecate and replace
template <typename Alloc, typename Alloc2>
void xor_buf(std::vector<uint8_t, Alloc>& out, const uint8_t* in, const std::vector<uint8_t, Alloc2>& in2, size_t n) {
   BOTAN_ARG_CHECK(out.size() >= n, "output vector is too small");
   BOTAN_ARG_CHECK(in2.size() >= n, "input vector is too small");
   // simply assumes that *in points to "n" allocated bytes at least
   xor_buf(std::span{out}.first(n), std::span{in, n}, std::span{in2}.first(n));
}

template <typename Alloc, typename Alloc2>
std::vector<uint8_t, Alloc>& operator^=(std::vector<uint8_t, Alloc>& out, const std::vector<uint8_t, Alloc2>& in) {
   if(out.size() < in.size()) {
      out.resize(in.size());
   }

   xor_buf(std::span{out}.first(in.size()), in);
   return out;
}

}  // namespace Botan

namespace Botan {

class RandomNumberGenerator;

/**
* Octet String
*/
class BOTAN_PUBLIC_API(2, 0) OctetString final {
   public:
      /**
      * @return size of this octet string in bytes
      */
      size_t length() const { return m_data.size(); }

      size_t size() const { return m_data.size(); }

      bool empty() const { return m_data.empty(); }

      /**
      * @return this object as a secure_vector<uint8_t>
      */
      secure_vector<uint8_t> bits_of() const { return m_data; }

      /**
      * @return start of this string
      */
      const uint8_t* begin() const { return m_data.data(); }

      /**
      * @return end of this string
      */
      const uint8_t* end() const { return begin() + m_data.size(); }

      /**
      * @return this encoded as hex
      */
      std::string to_string() const;

      /**
      * XOR the contents of another octet string into this one
      * @param other octet string
      * @return reference to this
      */
      OctetString& operator^=(const OctetString& other);

      /**
      * Force to have odd parity
      *
      * Deprecated. There is no reason to use this outside of interacting with
      * some very old or weird system which requires DES and also which do not
      * automatically ignore the parity bits.
      */
      BOTAN_DEPRECATED("Why would you need to do this")
      void set_odd_parity();

      /**
      * Create a new OctetString
      * @param str is a hex encoded string
      */
      explicit OctetString(std::string_view str = "");

      /**
      * Create a new random OctetString
      * @param rng is a random number generator
      * @param len is the desired length in bytes
      */
      OctetString(RandomNumberGenerator& rng, size_t len);

      /**
      * Create a new OctetString
      * @param in is an array
      * @param len is the length of in in bytes
      */
      OctetString(const uint8_t in[], size_t len);

      /**
      * Create a new OctetString
      * @param in a bytestring
      */
      explicit OctetString(std::span<const uint8_t> in) : m_data(in.begin(), in.end()) {}

      /**
      * Create a new OctetString
      * @param in a bytestring
      */
      explicit OctetString(secure_vector<uint8_t> in) : m_data(std::move(in)) {}

   private:
      secure_vector<uint8_t> m_data;
};

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is equal to y
*/
BOTAN_PUBLIC_API(2, 0) bool operator==(const OctetString& x, const OctetString& y);

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is not equal to y
*/
BOTAN_PUBLIC_API(2, 0) bool operator!=(const OctetString& x, const OctetString& y);

/**
* Concatenate two strings
* @param x an octet string
* @param y an octet string
* @return x concatenated with y
*/
BOTAN_PUBLIC_API(2, 0) OctetString operator+(const OctetString& x, const OctetString& y);

/**
* XOR two strings
* @param x an octet string
* @param y an octet string
* @return x XORed with y
*/
BOTAN_PUBLIC_API(2, 0) OctetString operator^(const OctetString& x, const OctetString& y);

/**
* Alternate name for octet string showing intent to use as a key
*/
using SymmetricKey = OctetString;

/**
* Alternate name for octet string showing intent to use as an IV
*/
using InitializationVector = OctetString;

}  // namespace Botan


namespace Botan {

/**
* Represents the length requirements on an algorithm key
*/
class BOTAN_PUBLIC_API(2, 0) Key_Length_Specification final {
   public:
      /**
      * Constructor for fixed length keys
      * @param keylen the supported key length
      */
      explicit Key_Length_Specification(size_t keylen) : m_min_keylen(keylen), m_max_keylen(keylen), m_keylen_mod(1) {}

      /**
      * Constructor for variable length keys
      * @param min_k the smallest supported key length
      * @param max_k the largest supported key length
      * @param k_mod the number of bytes the key must be a multiple of
      */
      Key_Length_Specification(size_t min_k, size_t max_k, size_t k_mod = 1) :
            m_min_keylen(min_k), m_max_keylen(max_k ? max_k : min_k), m_keylen_mod(k_mod) {}

      /**
      * @param length is a key length in bytes
      * @return true iff this length is a valid length for this algo
      */
      bool valid_keylength(size_t length) const {
         return ((length >= m_min_keylen) && (length <= m_max_keylen) && (length % m_keylen_mod == 0));
      }

      /**
      * @return minimum key length in bytes
      */
      size_t minimum_keylength() const { return m_min_keylen; }

      /**
      * @return maximum key length in bytes
      */
      size_t maximum_keylength() const { return m_max_keylen; }

      /**
      * @return key length multiple in bytes
      */
      size_t keylength_multiple() const { return m_keylen_mod; }

      /*
      * Multiplies all length requirements with the given factor
      * @param n the multiplication factor
      * @return a key length specification multiplied by the factor
      */
      Key_Length_Specification multiple(size_t n) const {
         return Key_Length_Specification(n * m_min_keylen, n * m_max_keylen, n * m_keylen_mod);
      }

   private:
      size_t m_min_keylen, m_max_keylen, m_keylen_mod;
};

/**
* This class represents a symmetric algorithm object.
*/
class BOTAN_PUBLIC_API(2, 0) SymmetricAlgorithm {
   public:
      virtual ~SymmetricAlgorithm() = default;

      /**
      * Reset the internal state. This includes not just the key, but
      * any partial message that may have been in process.
      */
      virtual void clear() = 0;

      /**
      * @return object describing limits on key size
      */
      virtual Key_Length_Specification key_spec() const = 0;

      /**
      * @return maximum allowed key length
      */
      size_t maximum_keylength() const { return key_spec().maximum_keylength(); }

      /**
      * @return minimum allowed key length
      */
      size_t minimum_keylength() const { return key_spec().minimum_keylength(); }

      /**
      * Check whether a given key length is valid for this algorithm.
      * @param length the key length to be checked.
      * @return true if the key length is valid.
      */
      bool valid_keylength(size_t length) const { return key_spec().valid_keylength(length); }

      /**
      * Set the symmetric key of this object.
      * @param key the SymmetricKey to be set.
      */
      void set_key(const SymmetricKey& key) { set_key(std::span{key.begin(), key.length()}); }

      /**
      * Set the symmetric key of this object.
      * @param key the contiguous byte range to be set.
      */
      void set_key(std::span<const uint8_t> key);

      /**
      * Set the symmetric key of this object.
      * @param key the to be set as a byte array.
      * @param length in bytes of key param
      */
      void set_key(const uint8_t key[], size_t length) { set_key(std::span{key, length}); }

      /**
      * @return the algorithm name
      */
      virtual std::string name() const = 0;

      /**
      * @return true if a key has been set on this object
      */
      virtual bool has_keying_material() const = 0;

   protected:
      void assert_key_material_set() const { assert_key_material_set(has_keying_material()); }

      void assert_key_material_set(bool predicate) const {
         if(!predicate) {
            throw_key_not_set_error();
         }
      }

   private:
      void throw_key_not_set_error() const;

      /**
      * Run the key schedule
      * @param key the key
      */
      virtual void key_schedule(std::span<const uint8_t> key) = 0;
};

}  // namespace Botan

namespace Botan {

/**
* This class represents a block cipher object.
*/
class BOTAN_PUBLIC_API(2, 0) BlockCipher : public SymmetricAlgorithm {
   public:
      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<BlockCipher> create(std::string_view algo_spec, std::string_view provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<BlockCipher> create_or_throw(std::string_view algo_spec, std::string_view provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      * @param algo_spec algorithm name
      */
      static std::vector<std::string> providers(std::string_view algo_spec);

      /**
      * @return block size of this algorithm
      */
      virtual size_t block_size() const = 0;

      /**
      * @return native parallelism of this cipher in blocks
      */
      virtual size_t parallelism() const { return 1; }

      /**
      * @return prefererred parallelism of this cipher in bytes
      */
      size_t parallel_bytes() const { return parallelism() * block_size() * BOTAN_BLOCK_CIPHER_PAR_MULT; }

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

      /**
      * Encrypt a block.
      * @param in The plaintext block to be encrypted as a byte array.
      * Must be of length block_size().
      * @param out The byte array designated to hold the encrypted block.
      * Must be of length block_size().
      */
      void encrypt(const uint8_t in[], uint8_t out[]) const { encrypt_n(in, out, 1); }

      /**
      * Decrypt a block.
      * @param in The ciphertext block to be decypted as a byte array.
      * Must be of length block_size().
      * @param out The byte array designated to hold the decrypted block.
      * Must be of length block_size().
      */
      void decrypt(const uint8_t in[], uint8_t out[]) const { decrypt_n(in, out, 1); }

      /**
      * Encrypt a block.
      * @param block the plaintext block to be encrypted
      * Must be of length block_size(). Will hold the result when the function
      * has finished.
      */
      void encrypt(uint8_t block[]) const { encrypt_n(block, block, 1); }

      /**
      * Decrypt a block.
      * @param block the ciphertext block to be decrypted
      * Must be of length block_size(). Will hold the result when the function
      * has finished.
      */
      void decrypt(uint8_t block[]) const { decrypt_n(block, block, 1); }

      /**
      * Encrypt one or more blocks
      * @param block the input/output buffer (multiple of block_size())
      */
      void encrypt(std::span<uint8_t> block) const {
         return encrypt_n(block.data(), block.data(), block.size() / block_size());
      }

      /**
      * Decrypt one or more blocks
      * @param block the input/output buffer (multiple of block_size())
      */
      void decrypt(std::span<uint8_t> block) const {
         return decrypt_n(block.data(), block.data(), block.size() / block_size());
      }

      /**
      * Encrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      */
      void encrypt(std::span<const uint8_t> in, std::span<uint8_t> out) const {
         return encrypt_n(in.data(), out.data(), in.size() / block_size());
      }

      /**
      * Decrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      */
      void decrypt(std::span<const uint8_t> in, std::span<uint8_t> out) const {
         return decrypt_n(in.data(), out.data(), in.size() / block_size());
      }

      /**
      * Encrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      * @param blocks the number of blocks to process
      */
      virtual void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const = 0;

      /**
      * Decrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      * @param blocks the number of blocks to process
      */
      virtual void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const = 0;

      virtual void encrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const {
         const size_t BS = block_size();
         xor_buf(data, mask, blocks * BS);
         encrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
      }

      virtual void decrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const {
         const size_t BS = block_size();
         xor_buf(data, mask, blocks * BS);
         decrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
      }

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<BlockCipher> new_object() const = 0;

      BlockCipher* clone() const { return this->new_object().release(); }

      ~BlockCipher() override = default;
};

/**
* Tweakable block ciphers allow setting a tweak which is a non-keyed
* value which affects the encryption/decryption operation.
*/
class BOTAN_PUBLIC_API(2, 8) Tweakable_Block_Cipher : public BlockCipher {
   public:
      /**
      * Set the tweak value. This must be called after setting a key. The value
      * persists until either set_tweak, set_key, or clear is called.
      * Different algorithms support different tweak length(s). If called with
      * an unsupported length, Invalid_Argument will be thrown.
      */
      virtual void set_tweak(const uint8_t tweak[], size_t len) = 0;
};

/**
* Represents a block cipher with a single fixed block size
*/
template <size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1, typename BaseClass = BlockCipher>
class Block_Cipher_Fixed_Params : public BaseClass {
   public:
      enum { BLOCK_SIZE = BS };

      size_t block_size() const final { return BS; }

      // override to take advantage of compile time constant block size
      void encrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const final {
         xor_buf(data, mask, blocks * BS);
         this->encrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
      }

      void decrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const final {
         xor_buf(data, mask, blocks * BS);
         this->decrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
      }

      Key_Length_Specification key_spec() const final { return Key_Length_Specification(KMIN, KMAX, KMOD); }
};

}  // namespace Botan

namespace Botan {

/**
* This class represents any kind of computation which uses an internal
* state, such as hash functions or MACs
*/
class BOTAN_PUBLIC_API(2, 0) Buffered_Computation {
   public:
      /**
      * @return length of the output of this function in bytes
      */
      virtual size_t output_length() const = 0;

      /**
      * Add new input to process.
      * @param in the input to process as a byte array
      * @param length of param in in bytes
      */
      void update(const uint8_t in[], size_t length) { add_data({in, length}); }

      /**
      * Add new input to process.
      * @param in the input to process as a contiguous data range
      */
      void update(std::span<const uint8_t> in) { add_data(in); }

      void update_be(uint16_t val);
      void update_be(uint32_t val);
      void update_be(uint64_t val);

      void update_le(uint16_t val);
      void update_le(uint32_t val);
      void update_le(uint64_t val);

      /**
      * Add new input to process.
      * @param str the input to process as a std::string_view. Will be interpreted
      * as a byte array based on the strings encoding.
      */
      void update(std::string_view str) { add_data({cast_char_ptr_to_uint8(str.data()), str.size()}); }

      /**
      * Process a single byte.
      * @param in the byte to process
      */
      void update(uint8_t in) { add_data({&in, 1}); }

      /**
      * Complete the computation and retrieve the
      * final result.
      * @param out The byte array to be filled with the result.
      * Must be of length output_length()
      */
      void final(uint8_t out[]) { final_result({out, output_length()}); }

      /**
      * Complete the computation and retrieve the
      * final result as a container of your choice.
      * @return a contiguous container holding the result
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T final() {
         T output(output_length());
         final_result(output);
         return output;
      }

      std::vector<uint8_t> final_stdvec() { return final<std::vector<uint8_t>>(); }

      void final(std::span<uint8_t> out) {
         BOTAN_ARG_CHECK(out.size() >= output_length(), "provided output buffer has insufficient capacity");
         final_result(out);
      }

      template <concepts::resizable_byte_buffer T>
      void final(T& out) {
         out.resize(output_length());
         final_result(out);
      }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a byte array
      * @param length the length of the byte array
      * @result the result of the call to final()
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T process(const uint8_t in[], size_t length) {
         update(in, length);
         return final<T>();
      }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a string
      * @result the result of the call to final()
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T process(std::string_view in) {
         update(in);
         return final<T>();
      }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a contiguous container
      * @result the result of the call to final()
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T process(std::span<const uint8_t> in) {
         update(in);
         return final<T>();
      }

      virtual ~Buffered_Computation() = default;

   private:
      /**
      * Add more data to the computation
      * @param input is an input buffer
      */
      virtual void add_data(std::span<const uint8_t> input) = 0;

      /**
      * Write the final output to out
      * @param out is an output buffer of output_length()
      */
      virtual void final_result(std::span<uint8_t> out) = 0;
};

}  // namespace Botan

namespace Botan {

/**
* This class represents an abstract data source object.
*/
class BOTAN_PUBLIC_API(2, 0) DataSource {
   public:
      /**
      * Read from the source. Moves the internal offset so that every
      * call to read will return a new portion of the source.
      *
      * @param out the byte array to write the result to
      * @param length the length of the byte array out
      * @return length in bytes that was actually read and put
      * into out
      */
      [[nodiscard]] virtual size_t read(uint8_t out[], size_t length) = 0;

      virtual bool check_available(size_t n) = 0;

      /**
      * Read from the source but do not modify the internal
      * offset. Consecutive calls to peek() will return portions of
      * the source starting at the same position.
      *
      * @param out the byte array to write the output to
      * @param length the length of the byte array out
      * @param peek_offset the offset into the stream to read at
      * @return length in bytes that was actually read and put
      * into out
      */
      [[nodiscard]] virtual size_t peek(uint8_t out[], size_t length, size_t peek_offset) const = 0;

      /**
      * Test whether the source still has data that can be read.
      * @return true if there is no more data to read, false otherwise
      */
      virtual bool end_of_data() const = 0;

      /**
      * return the id of this data source
      * @return std::string representing the id of this data source
      */
      virtual std::string id() const { return ""; }

      /**
      * Read one byte.
      * @param out the byte to read to
      * @return length in bytes that was actually read and put
      * into out
      */
      size_t read_byte(uint8_t& out);

      /**
      * Peek at one byte.
      * @param out an output byte
      * @return length in bytes that was actually read and put
      * into out
      */
      size_t peek_byte(uint8_t& out) const;

      /**
      * Discard the next N bytes of the data
      * @param N the number of bytes to discard
      * @return number of bytes actually discarded
      */
      size_t discard_next(size_t N);

      /**
      * @return number of bytes read so far.
      */
      virtual size_t get_bytes_read() const = 0;

      DataSource() = default;
      virtual ~DataSource() = default;
      DataSource& operator=(const DataSource&) = delete;
      DataSource(const DataSource&) = delete;
};

/**
* This class represents a Memory-Based DataSource
*/
class BOTAN_PUBLIC_API(2, 0) DataSource_Memory final : public DataSource {
   public:
      size_t read(uint8_t[], size_t) override;
      size_t peek(uint8_t[], size_t, size_t) const override;
      bool check_available(size_t n) override;
      bool end_of_data() const override;

      /**
      * Construct a memory source that reads from a string
      * @param in the string to read from
      */
      explicit DataSource_Memory(std::string_view in);

      /**
      * Construct a memory source that reads from a byte array
      * @param in the byte array to read from
      * @param length the length of the byte array
      */
      DataSource_Memory(const uint8_t in[], size_t length) : m_source(in, in + length), m_offset(0) {}

      /**
      * Construct a memory source that reads from a secure_vector
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(secure_vector<uint8_t> in) : m_source(std::move(in)), m_offset(0) {}

      /**
      * Construct a memory source that reads from an arbitrary byte buffer
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(std::span<const uint8_t> in) : m_source(in.begin(), in.end()), m_offset(0) {}

      /**
      * Construct a memory source that reads from a std::vector
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(const std::vector<uint8_t>& in) : m_source(in.begin(), in.end()), m_offset(0) {}

      size_t get_bytes_read() const override { return m_offset; }

   private:
      secure_vector<uint8_t> m_source;
      size_t m_offset;
};

/**
* This class represents a Stream-Based DataSource.
*/
class BOTAN_PUBLIC_API(2, 0) DataSource_Stream final : public DataSource {
   public:
      size_t read(uint8_t[], size_t) override;
      size_t peek(uint8_t[], size_t, size_t) const override;
      bool check_available(size_t n) override;
      bool end_of_data() const override;
      std::string id() const override;

      DataSource_Stream(std::istream&, std::string_view id = "<std::istream>");

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Construct a Stream-Based DataSource from filesystem path
      * @param filename the path to the file
      * @param use_binary whether to treat the file as binary or not
      */
      DataSource_Stream(std::string_view filename, bool use_binary = false);
#endif

      DataSource_Stream(const DataSource_Stream&) = delete;

      DataSource_Stream& operator=(const DataSource_Stream&) = delete;

      ~DataSource_Stream() override;

      size_t get_bytes_read() const override { return m_total_read; }

   private:
      const std::string m_identifier;

      std::unique_ptr<std::istream> m_source_memory;
      std::istream& m_source;
      size_t m_total_read;
};

}  // namespace Botan

namespace Botan {

/**
* Different types of errors that might occur
*/
enum class ErrorType {
   /** Some unknown error */
   Unknown = 1,
   /** An error while calling a system interface */
   SystemError,
   /** An operation seems valid, but not supported by the current version */
   NotImplemented,
   /** Memory allocation failure */
   OutOfMemory,
   /** An internal error occurred */
   InternalError,
   /** An I/O error occurred */
   IoError,

   /** Invalid object state */
   InvalidObjectState = 100,
   /** A key was not set on an object when this is required */
   KeyNotSet,
   /** The application provided an argument which is invalid */
   InvalidArgument,
   /** A key with invalid length was provided */
   InvalidKeyLength,
   /** A nonce with invalid length was provided */
   InvalidNonceLength,
   /** An object type was requested but cannot be found */
   LookupError,
   /** Encoding a message or datum failed */
   EncodingFailure,
   /** Decoding a message or datum failed */
   DecodingFailure,
   /** A TLS error (error_code will be the alert type) */
   TLSError,
   /** An error during an HTTP operation */
   HttpError,
   /** A message with an invalid authentication tag was detected */
   InvalidTag,
   /** An error during Roughtime validation */
   RoughtimeError,

   /** An error when interacting with CommonCrypto API */
   CommonCryptoError = 201,
   /** An error when interacting with a PKCS11 device */
   Pkcs11Error,
   /** An error when interacting with a TPM device */
   TPMError,
   /** An error when interacting with a database */
   DatabaseError,

   /** An error when interacting with zlib */
   ZlibError = 300,
   /** An error when interacting with bzip2 */
   Bzip2Error,
   /** An error when interacting with lzma */
   LzmaError,

};

//! \brief Convert an ErrorType to string
std::string BOTAN_PUBLIC_API(2, 11) to_string(ErrorType type);

/**
* Base class for all exceptions thrown by the library
*/
class BOTAN_PUBLIC_API(2, 0) Exception : public std::exception {
   public:
      /**
      * Return a descriptive string which is hopefully comprehensible to
      * a developer. It will likely not be useful for an end user.
      *
      * The string has no particular format, and the content of exception
      * messages may change from release to release. Thus the main use of this
      * function is for logging or debugging.
      */
      const char* what() const noexcept override { return m_msg.c_str(); }

      /**
      * Return the "type" of error which occurred.
      */
      virtual ErrorType error_type() const noexcept { return ErrorType::Unknown; }

      /**
      * Return an error code associated with this exception, or otherwise 0.
      *
      * The domain of this error varies depending on the source, for example on
      * POSIX systems it might be errno, while on a Windows system it might be
      * the result of GetLastError or WSAGetLastError.
      */
      virtual int error_code() const noexcept { return 0; }

      /**
      * Avoid throwing base Exception, use a subclass
      */
      explicit Exception(std::string_view msg);

      /**
      * Avoid throwing base Exception, use a subclass
      */
      Exception(const char* prefix, std::string_view msg);

      /**
      * Avoid throwing base Exception, use a subclass
      */
      Exception(std::string_view msg, const std::exception& e);

   private:
      std::string m_msg;
};

/**
* An invalid argument was provided to an API call.
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_Argument : public Exception {
   public:
      explicit Invalid_Argument(std::string_view msg);

      explicit Invalid_Argument(std::string_view msg, std::string_view where);

      Invalid_Argument(std::string_view msg, const std::exception& e);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidArgument; }
};

/**
* An invalid/unknown field name was passed to Public_Key::get_int_field
*/
class BOTAN_PUBLIC_API(3, 0) Unknown_PK_Field_Name final : public Invalid_Argument {
   public:
      Unknown_PK_Field_Name(std::string_view algo_name, std::string_view field_name);
};

/**
* An invalid key length was used
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_Key_Length final : public Invalid_Argument {
   public:
      Invalid_Key_Length(std::string_view name, size_t length);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidKeyLength; }
};

/**
* An invalid nonce length was used
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_IV_Length final : public Invalid_Argument {
   public:
      Invalid_IV_Length(std::string_view mode, size_t bad_len);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidNonceLength; }
};

/**
* Invalid_Algorithm_Name Exception
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_Algorithm_Name final : public Invalid_Argument {
   public:
      explicit Invalid_Algorithm_Name(std::string_view name);
};

/**
* Encoding_Error Exception
*/
class BOTAN_PUBLIC_API(2, 0) Encoding_Error final : public Exception {
   public:
      explicit Encoding_Error(std::string_view name);

      ErrorType error_type() const noexcept override { return ErrorType::EncodingFailure; }
};

/**
* A decoding error occurred.
*/
class BOTAN_PUBLIC_API(2, 0) Decoding_Error : public Exception {
   public:
      explicit Decoding_Error(std::string_view name);

      Decoding_Error(std::string_view category, std::string_view err);

      Decoding_Error(std::string_view msg, const std::exception& e);

      ErrorType error_type() const noexcept override { return ErrorType::DecodingFailure; }
};

/**
* Invalid state was encountered. A request was made on an object while the
* object was in a state where the operation cannot be performed.
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_State : public Exception {
   public:
      explicit Invalid_State(std::string_view err) : Exception(err) {}

      ErrorType error_type() const noexcept override { return ErrorType::InvalidObjectState; }
};

/**
* A PRNG was called on to produce output while still unseeded
*/
class BOTAN_PUBLIC_API(2, 0) PRNG_Unseeded final : public Invalid_State {
   public:
      explicit PRNG_Unseeded(std::string_view algo);
};

/**
* The key was not set on an object. This occurs with symmetric objects where
* an operation which requires the key is called prior to set_key being called.
*/
class BOTAN_PUBLIC_API(2, 4) Key_Not_Set : public Invalid_State {
   public:
      explicit Key_Not_Set(std::string_view algo);

      ErrorType error_type() const noexcept override { return ErrorType::KeyNotSet; }
};

/**
* A request was made for some kind of object which could not be located
*/
class BOTAN_PUBLIC_API(2, 0) Lookup_Error : public Exception {
   public:
      explicit Lookup_Error(std::string_view err) : Exception(err) {}

      Lookup_Error(std::string_view type, std::string_view algo, std::string_view provider = "");

      ErrorType error_type() const noexcept override { return ErrorType::LookupError; }
};

/**
* Algorithm_Not_Found Exception
*
* @warning This exception type will be removed in the future. Instead
* just catch Lookup_Error.
*/
class BOTAN_PUBLIC_API(2, 0) Algorithm_Not_Found final : public Lookup_Error {
   public:
      explicit Algorithm_Not_Found(std::string_view name);
};

/**
* Provider_Not_Found is thrown when a specific provider was requested
* but that provider is not available.
*
* @warning This exception type will be removed in the future. Instead
* just catch Lookup_Error.
*/
class BOTAN_PUBLIC_API(2, 0) Provider_Not_Found final : public Lookup_Error {
   public:
      Provider_Not_Found(std::string_view algo, std::string_view provider);
};

/**
* An AEAD or MAC check detected a message modification
*
* In versions before 2.10, Invalid_Authentication_Tag was named
* Integrity_Failure, it was renamed to make its usage more clear.
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_Authentication_Tag final : public Exception {
   public:
      explicit Invalid_Authentication_Tag(std::string_view msg);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidTag; }
};

/**
* For compatability with older versions
*/
typedef Invalid_Authentication_Tag Integrity_Failure;

/**
* An error occurred while operating on an IO stream
*/
class BOTAN_PUBLIC_API(2, 0) Stream_IO_Error final : public Exception {
   public:
      explicit Stream_IO_Error(std::string_view err);

      ErrorType error_type() const noexcept override { return ErrorType::IoError; }
};

/**
* System_Error
*
* This exception is thrown in the event of an error related to interacting
* with the operating system.
*
* This exception type also (optionally) captures an integer error code eg
* POSIX errno or Windows GetLastError.
*/
class BOTAN_PUBLIC_API(2, 9) System_Error : public Exception {
   public:
      System_Error(std::string_view msg) : Exception(msg), m_error_code(0) {}

      System_Error(std::string_view msg, int err_code);

      ErrorType error_type() const noexcept override { return ErrorType::SystemError; }

      int error_code() const noexcept override { return m_error_code; }

   private:
      int m_error_code;
};

/**
* An internal error occurred. If observed, please file a bug.
*/
class BOTAN_PUBLIC_API(2, 0) Internal_Error : public Exception {
   public:
      explicit Internal_Error(std::string_view err);

      ErrorType error_type() const noexcept override { return ErrorType::InternalError; }
};

/**
* Not Implemented Exception
*
* This is thrown in the situation where a requested operation is
* logically valid but is not implemented by this version of the library.
*/
class BOTAN_PUBLIC_API(2, 0) Not_Implemented final : public Exception {
   public:
      explicit Not_Implemented(std::string_view err);

      ErrorType error_type() const noexcept override { return ErrorType::NotImplemented; }
};

template <typename E, typename... Args>
inline void do_throw_error(const char* file, int line, const char* func, Args... args) {
   throw E(file, line, func, args...);
}

}  // namespace Botan

namespace Botan {

class BOTAN_PUBLIC_API(2, 0) SQL_Database {
   public:
      class BOTAN_PUBLIC_API(2, 0) SQL_DB_Error final : public Exception {
         public:
            explicit SQL_DB_Error(std::string_view what) : Exception("SQL database", what), m_rc(0) {}

            SQL_DB_Error(std::string_view what, int rc) : Exception("SQL database", what), m_rc(rc) {}

            ErrorType error_type() const noexcept override { return ErrorType::DatabaseError; }

            int error_code() const noexcept override { return m_rc; }

         private:
            int m_rc;
      };

      class BOTAN_PUBLIC_API(2, 0) Statement {
         public:
            /* Bind statement parameters */
            virtual void bind(int column, std::string_view str) = 0;

            virtual void bind(int column, size_t i) = 0;

            virtual void bind(int column, std::chrono::system_clock::time_point time) = 0;

            virtual void bind(int column, const std::vector<uint8_t>& blob) = 0;

            virtual void bind(int column, const uint8_t* data, size_t len) = 0;

            /* Get output */
            virtual std::pair<const uint8_t*, size_t> get_blob(int column) = 0;

            virtual std::string get_str(int column) = 0;

            virtual size_t get_size_t(int column) = 0;

            /* Run to completion */
            virtual size_t spin() = 0;

            /* Maybe update */
            virtual bool step() = 0;

            virtual ~Statement() = default;
      };

      /*
      * Create a new statement for execution.
      * Use ?1, ?2, ?3, etc for parameters to set later with bind
      */
      virtual std::shared_ptr<Statement> new_statement(std::string_view base_sql) const = 0;

      virtual size_t row_count(std::string_view table_name) = 0;

      virtual void create_table(std::string_view table_schema) = 0;

      virtual size_t rows_changed_by_last_statement() = 0;

      virtual size_t exec(std::string_view sql) { return new_statement(sql)->spin(); }

      virtual bool is_threadsafe() const { return false; }

      virtual ~SQL_Database() = default;
};

}  // namespace Botan

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   #include <mutex>
#endif

namespace Botan {

#if defined(BOTAN_TARGET_OS_HAS_THREADS)

using mutex_type = std::mutex;
using recursive_mutex_type = std::recursive_mutex;

template <typename T>
using lock_guard_type = std::lock_guard<T>;

#else

// No threads

class noop_mutex final {
   public:
      void lock() {}

      void unlock() {}
};

using mutex_type = noop_mutex;
using recursive_mutex_type = noop_mutex;

template <typename Mutex>
class lock_guard final {
   public:
      explicit lock_guard(Mutex& m) : m_mutex(m) { m_mutex.lock(); }

      ~lock_guard() { m_mutex.unlock(); }

      lock_guard(const lock_guard& other) = delete;
      lock_guard& operator=(const lock_guard& other) = delete;

   private:
      Mutex& m_mutex;
};

template <typename T>
using lock_guard_type = lock_guard<T>;

#endif

}  // namespace Botan


namespace Botan {

class Entropy_Sources;

/**
* An interface to a cryptographic random number generator
*/
class BOTAN_PUBLIC_API(2, 0) RandomNumberGenerator {
   public:
      virtual ~RandomNumberGenerator() = default;

      RandomNumberGenerator() = default;

      /*
      * Never copy a RNG, create a new one
      */
      RandomNumberGenerator(const RandomNumberGenerator& rng) = delete;
      RandomNumberGenerator& operator=(const RandomNumberGenerator& rng) = delete;

      /**
      * Randomize a byte array.
      *
      * May block shortly if e.g. the RNG is not yet initialized
      * or a retry because of insufficient entropy is needed.
      *
      * @param output the byte array to hold the random output.
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      void randomize(std::span<uint8_t> output) { this->fill_bytes_with_input(output, {}); }

      void randomize(uint8_t output[], size_t length) { this->randomize(std::span(output, length)); }

      /**
      * Returns false if it is known that this RNG object is not able to accept
      * externally provided inputs (via add_entropy, randomize_with_input, etc).
      * In this case, any such provided inputs are ignored.
      *
      * If this function returns true, then inputs may or may not be accepted.
      */
      virtual bool accepts_input() const = 0;

      /**
      * Incorporate some additional data into the RNG state. For
      * example adding nonces or timestamps from a peer's protocol
      * message can help hedge against VM state rollback attacks.
      * A few RNG types do not accept any externally provided input,
      * in which case this function is a no-op.
      *
      * @param input a byte array containing the entropy to be added
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      void add_entropy(std::span<const uint8_t> input) { this->fill_bytes_with_input({}, input); }

      void add_entropy(const uint8_t input[], size_t length) { this->add_entropy(std::span(input, length)); }

      /**
      * Incorporate some additional data into the RNG state.
      */
      template <typename T>
         requires std::is_standard_layout<T>::value && std::is_trivial<T>::value
      void add_entropy_T(const T& t) {
         this->add_entropy(reinterpret_cast<const uint8_t*>(&t), sizeof(T));
      }

      /**
      * Incorporate entropy into the RNG state then produce output.
      * Some RNG types implement this using a single operation, default
      * calls add_entropy + randomize in sequence.
      *
      * Use this to further bind the outputs to your current
      * process/protocol state. For instance if generating a new key
      * for use in a session, include a session ID or other such
      * value. See NIST SP 800-90 A, B, C series for more ideas.
      *
      * @param output buffer to hold the random output
      * @param input entropy buffer to incorporate
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      void randomize_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
         this->fill_bytes_with_input(output, input);
      }

      void randomize_with_input(uint8_t output[], size_t output_len, const uint8_t input[], size_t input_len) {
         this->randomize_with_input(std::span(output, output_len), std::span(input, input_len));
      }

      /**
      * This calls `randomize_with_input` using some timestamps as extra input.
      *
      * For a stateful RNG using non-random but potentially unique data the
      * extra input can help protect against problems with fork, VM state
      * rollback, or other cases where somehow an RNG state is duplicated. If
      * both of the duplicated RNG states later incorporate a timestamp (and the
      * timestamps don't themselves repeat), their outputs will diverge.
      *
      * @param output buffer to hold the random output
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      void randomize_with_ts_input(std::span<uint8_t> output);

      void randomize_with_ts_input(uint8_t output[], size_t output_len) {
         this->randomize_with_ts_input(std::span(output, output_len));
      }

      /**
      * @return the name of this RNG type
      */
      virtual std::string name() const = 0;

      /**
      * Clear all internally held values of this RNG
      * @post is_seeded() == false if the RNG has an internal state that can be cleared.
      */
      virtual void clear() = 0;

      /**
      * Check whether this RNG is seeded.
      * @return true if this RNG was already seeded, false otherwise.
      */
      virtual bool is_seeded() const = 0;

      /**
      * Poll provided sources for up to poll_bits bits of entropy
      * or until the timeout expires. Returns estimate of the number
      * of bits collected.
      *
      * Sets the seeded state to true if enough entropy was added.
      */
      virtual size_t reseed(Entropy_Sources& srcs,
                            size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                            std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT);

      /**
      * Reseed by reading specified bits from the RNG
      *
      * Sets the seeded state to true if enough entropy was added.
      *
      * @throws Exception if RNG accepts input but reseeding failed.
      */
      virtual void reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS);

      // Some utility functions built on the interface above:

      /**
      * Fill a given byte container with @p bytes random bytes
      *
      * @todo deprecate this overload (in favor of randomize())
      *
      * @param  v     the container to be filled with @p bytes random bytes
      * @throws Exception if RNG fails
      */
      void random_vec(std::span<uint8_t> v) { this->randomize(v); }

      /**
      * Resize a given byte container to @p bytes and fill it with random bytes
      *
      * @tparam T     the desired byte container type (e.g std::vector<uint8_t>)
      * @param  v     the container to be filled with @p bytes random bytes
      * @param  bytes number of random bytes to initialize the container with
      * @throws Exception if RNG or memory allocation fails
      */
      template <concepts::resizable_byte_buffer T>
      void random_vec(T& v, size_t bytes) {
         v.resize(bytes);
         random_vec(v);
      }

      /**
      * Create some byte container type and fill it with some random @p bytes.
      *
      * @tparam T     the desired byte container type (e.g std::vector<uint8_t>)
      * @param  bytes number of random bytes to initialize the container with
      * @return       a container of type T with @p bytes random bytes
      * @throws Exception if RNG or memory allocation fails
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
         requires std::default_initializable<T>
      T random_vec(size_t bytes) {
         T result;
         random_vec(result, bytes);
         return result;
      }

      /**
      * Return a random byte
      * @return random byte
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      uint8_t next_byte() {
         uint8_t b;
         this->fill_bytes_with_input(std::span(&b, 1), {});
         return b;
      }

      /**
      * @return a random byte that is greater than zero
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      uint8_t next_nonzero_byte() {
         uint8_t b = this->next_byte();
         while(b == 0) {
            b = this->next_byte();
         }
         return b;
      }

   protected:
      /**
      * Generic interface to provide entropy to a concrete implementation and to
      * fill a given buffer with random output. Both @p output and @p input may
      * be empty and should be ignored in that case. If both buffers are
      * non-empty implementations should typically first apply the @p input data
      * and then generate random data into @p output.
      *
      * This method must be implemented by all RandomNumberGenerator sub-classes.
      *
      * @param output  Byte buffer to write random bytes into. Implementations
      *                should not read from this buffer.
      * @param input   Byte buffer that may contain bytes to be incorporated in
      *                the RNG's internal state. Implementations may choose to
      *                ignore the bytes in this buffer.
      */
      virtual void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) = 0;
};

/**
* Convenience typedef
*/
typedef RandomNumberGenerator RNG;

/**
* Hardware_RNG exists to tag hardware RNG types (PKCS11_RNG, TPM_RNG, Processor_RNG)
*/
class BOTAN_PUBLIC_API(2, 0) Hardware_RNG : public RandomNumberGenerator {
   public:
      void clear() final { /* no way to clear state of hardware RNG */
      }
};

/**
* Null/stub RNG - fails if you try to use it for anything
* This is not generally useful except for in certain tests
*/
class BOTAN_PUBLIC_API(2, 0) Null_RNG final : public RandomNumberGenerator {
   public:
      bool is_seeded() const override { return false; }

      bool accepts_input() const override { return false; }

      void clear() override {}

      std::string name() const override { return "Null_RNG"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override;
};

}  // namespace Botan

namespace Botan {

class RandomNumberGenerator;

/**
* Abstract interface to a source of entropy
*/
class BOTAN_PUBLIC_API(2, 0) Entropy_Source {
   public:
      /**
      * Return a new entropy source of a particular type, or null
      * Each entropy source may require substantial resources (eg, a file handle
      * or socket instance), so try to share them among multiple RNGs, or just
      * use the preconfigured global list accessed by Entropy_Sources::global_sources()
      */
      static std::unique_ptr<Entropy_Source> create(std::string_view type);

      /**
      * @return name identifying this entropy source
      */
      virtual std::string name() const = 0;

      /**
      * Perform an entropy gathering poll
      * @param rng will be provided with entropy via calls to add_entropy
      * @return conservative estimate of actual entropy added to rng during poll
      */
      virtual size_t poll(RandomNumberGenerator& rng) = 0;

      Entropy_Source() = default;
      Entropy_Source(const Entropy_Source& other) = delete;
      Entropy_Source(Entropy_Source&& other) = delete;
      Entropy_Source& operator=(const Entropy_Source& other) = delete;

      virtual ~Entropy_Source() = default;
};

class BOTAN_PUBLIC_API(2, 0) Entropy_Sources final {
   public:
      static Entropy_Sources& global_sources();

      void add_source(std::unique_ptr<Entropy_Source> src);

      std::vector<std::string> enabled_sources() const;

      size_t poll(RandomNumberGenerator& rng, size_t bits, std::chrono::milliseconds timeout);

      /**
      * Poll just a single named source. Ordinally only used for testing
      */
      size_t poll_just(RandomNumberGenerator& rng, std::string_view src);

      Entropy_Sources() = default;
      explicit Entropy_Sources(const std::vector<std::string>& sources);

      Entropy_Sources(const Entropy_Sources& other) = delete;
      Entropy_Sources(Entropy_Sources&& other) = delete;
      Entropy_Sources& operator=(const Entropy_Sources& other) = delete;

   private:
      std::vector<std::unique_ptr<Entropy_Source>> m_srcs;
};

}  // namespace Botan

namespace Botan {

/**
* Perform hex encoding
* @param output an array of at least input_length*2 bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
*/
void BOTAN_PUBLIC_API(2, 0)
   hex_encode(char output[], const uint8_t input[], size_t input_length, bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
std::string BOTAN_PUBLIC_API(2, 0) hex_encode(const uint8_t input[], size_t input_length, bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
inline std::string hex_encode(std::span<const uint8_t> input, bool uppercase = true) {
   return hex_encode(input.data(), input.size(), uppercase);
}

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*        bytes of input were actually consumed. If less than
*        input_length, then the range input[consumed:length]
*        should be passed in later along with more input.
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2, 0)
   hex_decode(uint8_t output[], const char input[], size_t input_length, size_t& input_consumed, bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2, 0)
   hex_decode(uint8_t output[], const char input[], size_t input_length, bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(3, 0) hex_decode(uint8_t output[], std::string_view input, bool ignore_ws = true);

/**
* Perform hex decoding
* @param output a contiguous byte buffer of at least input_length/2 bytes
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
*                  exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(3, 0) hex_decode(std::span<uint8_t> output, std::string_view input, bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
std::vector<uint8_t> BOTAN_PUBLIC_API(2, 0) hex_decode(const char input[], size_t input_length, bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
std::vector<uint8_t> BOTAN_PUBLIC_API(3, 0) hex_decode(std::string_view input, bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2, 0)
   hex_decode_locked(const char input[], size_t input_length, bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(3, 0) hex_decode_locked(std::string_view input, bool ignore_ws = true);

}  // namespace Botan


namespace Botan {

/**
 * Added as an additional "capability tag" to enable arithmetic operators with
 * plain numbers for Strong<> types that wrap a number.
 */
struct EnableArithmeticWithPlainNumber {};

namespace detail {

/**
 * Checks whether the @p CapabilityT is included in the @p Tags type pack.
 */
template <typename CapabilityT, typename... Tags>
constexpr bool has_capability = (std::is_same_v<CapabilityT, Tags> || ...);

template <typename T>
class Strong_Base {
   private:
      T m_value;

   public:
      using wrapped_type = T;

   public:
      Strong_Base() = default;
      Strong_Base(const Strong_Base&) = default;
      Strong_Base(Strong_Base&&) noexcept = default;
      Strong_Base& operator=(const Strong_Base&) = default;
      Strong_Base& operator=(Strong_Base&&) noexcept = default;

      constexpr explicit Strong_Base(T v) : m_value(std::move(v)) {}

      T& get() { return m_value; }

      const T& get() const { return m_value; }
};

template <typename T>
class Strong_Adapter : public Strong_Base<T> {
   public:
      using Strong_Base<T>::Strong_Base;
};

template <std::integral T>
class Strong_Adapter<T> : public Strong_Base<T> {
   public:
      using Strong_Base<T>::Strong_Base;
};

template <concepts::container T>
class Strong_Adapter<T> : public Strong_Base<T> {
   public:
      using value_type = typename T::value_type;
      using size_type = typename T::size_type;
      using iterator = typename T::iterator;
      using const_iterator = typename T::const_iterator;
      using pointer = typename T::pointer;
      using const_pointer = typename T::const_pointer;

   public:
      using Strong_Base<T>::Strong_Base;

      explicit Strong_Adapter(std::span<const value_type> span)
         requires(concepts::contiguous_container<T>)
            : Strong_Adapter(T(span.begin(), span.end())) {}

      explicit Strong_Adapter(size_t size)
         requires(concepts::resizable_container<T>)
            : Strong_Adapter(T(size)) {}

      template <typename InputIt>
      Strong_Adapter(InputIt begin, InputIt end) : Strong_Adapter(T(begin, end)) {}

      // Disambiguates the usage of string literals, otherwise:
      // Strong_Adapter(std::span<>) and Strong_Adapter(const char*)
      // would be ambiguous.
      explicit Strong_Adapter(const char* str)
         requires(std::same_as<T, std::string>)
            : Strong_Adapter(std::string(str)) {}

   public:
      decltype(auto) begin() noexcept(noexcept(this->get().begin())) { return this->get().begin(); }

      decltype(auto) begin() const noexcept(noexcept(this->get().begin())) { return this->get().begin(); }

      decltype(auto) end() noexcept(noexcept(this->get().end())) { return this->get().end(); }

      decltype(auto) end() const noexcept(noexcept(this->get().end())) { return this->get().end(); }

      decltype(auto) cbegin() noexcept(noexcept(this->get().cbegin())) { return this->get().cbegin(); }

      decltype(auto) cbegin() const noexcept(noexcept(this->get().cbegin())) { return this->get().cbegin(); }

      decltype(auto) cend() noexcept(noexcept(this->get().cend())) { return this->get().cend(); }

      decltype(auto) cend() const noexcept(noexcept(this->get().cend())) { return this->get().cend(); }

      size_type size() const noexcept(noexcept(this->get().size())) { return this->get().size(); }

      decltype(auto) data() noexcept(noexcept(this->get().data()))
         requires(concepts::contiguous_container<T>)
      {
         return this->get().data();
      }

      decltype(auto) data() const noexcept(noexcept(this->get().data()))
         requires(concepts::contiguous_container<T>)
      {
         return this->get().data();
      }

      bool empty() const noexcept(noexcept(this->get().empty()))
         requires(concepts::has_empty<T>)
      {
         return this->get().empty();
      }

      void resize(size_type size) noexcept(noexcept(this->get().resize(size)))
         requires(concepts::resizable_container<T>)
      {
         this->get().resize(size);
      }

      decltype(auto) operator[](size_type i) const noexcept(noexcept(this->get().operator[](i))) {
         return this->get()[i];
      }

      decltype(auto) operator[](size_type i) noexcept(noexcept(this->get().operator[](i))) { return this->get()[i]; }
};

}  // namespace detail

/**
 * Strong types can be used as wrappers around common types to provide
 * compile time semantics. They usually contribute to more maintainable and
 * less error-prone code especially when dealing with function parameters.
 *
 * Internally, this provides adapters so that the wrapping strong type behaves
 * as much as the underlying type as possible and desirable.
 *
 * This implementation was inspired by:
 *   https://stackoverflow.com/a/69030899
 */
template <typename T, typename TagTypeT, typename... Capabilities>
class Strong : public detail::Strong_Adapter<T> {
   public:
      using detail::Strong_Adapter<T>::Strong_Adapter;

   private:
      using Tag = TagTypeT;
};

template <typename T, typename... Tags>
   requires(concepts::streamable<T>) decltype(auto)
operator<<(std::ostream& os, const Strong<T, Tags...>& v) {
   return os << v.get();
}

template <typename T, typename... Tags>
   requires(std::equality_comparable<T>) bool
operator==(const Strong<T, Tags...>& lhs, const Strong<T, Tags...>& rhs) {
   return lhs.get() == rhs.get();
}

template <typename T, typename... Tags>
   requires(std::three_way_comparable<T>)
auto operator<=>(const Strong<T, Tags...>& lhs, const Strong<T, Tags...>& rhs) {
   return lhs.get() <=> rhs.get();
}

template <std::integral T1, std::integral T2, typename... Tags>
auto operator<=>(T1 a, Strong<T2, Tags...> b) {
   return a <=> b.get();
}

template <std::integral T1, std::integral T2, typename... Tags>
auto operator<=>(Strong<T1, Tags...> a, T2 b) {
   return a.get() <=> b;
}

template <std::integral T1, std::integral T2, typename... Tags>
auto operator==(T1 a, Strong<T2, Tags...> b) {
   return a == b.get();
}

template <std::integral T1, std::integral T2, typename... Tags>
auto operator==(Strong<T1, Tags...> a, T2 b) {
   return a.get() == b;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator+(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a + b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator+(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() + b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator+(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() + b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator-(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a - b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator-(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() - b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator-(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() - b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator*(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a * b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator*(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() * b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator*(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() * b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator/(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a / b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator/(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() / b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator/(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() / b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator^(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a ^ b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator^(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() ^ b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator^(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() ^ b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator&(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a & b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator&(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() & b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator&(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() & b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator|(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a | b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator|(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() | b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator|(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() | b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator>>(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a >> b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator>>(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() >> b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator>>(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() >> b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator<<(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a << b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator<<(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() << b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator<<(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() << b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator+=(Strong<T1, Tags...>& a, T2 b) {
   a.get() += b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator+=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() += b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator-=(Strong<T1, Tags...>& a, T2 b) {
   a.get() -= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator-=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() -= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator*=(Strong<T1, Tags...>& a, T2 b) {
   a.get() *= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator*=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() *= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator/=(Strong<T1, Tags...>& a, T2 b) {
   a.get() /= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator/=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() /= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator^=(Strong<T1, Tags...>& a, T2 b) {
   a.get() ^= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator^=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() ^= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator&=(Strong<T1, Tags...>& a, T2 b) {
   a.get() &= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator&=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() &= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator|=(Strong<T1, Tags...>& a, T2 b) {
   a.get() |= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator|=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() |= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator>>=(Strong<T1, Tags...>& a, T2 b) {
   a.get() >>= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator>>=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() >>= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator<<=(Strong<T1, Tags...>& a, T2 b) {
   a.get() <<= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator<<=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() <<= b.get();
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator++(Strong<T, Tags...>& a, int) {
   auto tmp = a;
   ++a.get();
   return tmp;
}

template <std::integral T, typename... Tags>
constexpr auto operator++(Strong<T, Tags...>& a) {
   ++a.get();
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator--(Strong<T, Tags...>& a, int) {
   auto tmp = a;
   --a.get();
   return tmp;
}

template <std::integral T, typename... Tags>
constexpr auto operator--(Strong<T, Tags...>& a) {
   --a.get();
   return a;
}

/**
 * This mimmicks a std::span but keeps track of the strong-type information. Use
 * this when you would want to use `const Strong<...>&` as a parameter
 * declaration. In particular this allows assigning strong-type information to
 * slices of a bigger buffer without copying the bytes. E.g:
 *
 *    using Foo = Strong<std::vector<uint8_t>, Foo_>;
 *
 *    void bar(StrongSpan<Foo> foo) { ... }
 *
 *    std::vector<uint8_t> buffer;
 *    BufferSlicer slicer(buffer);
 *    bar(slicer.take<Foo>());  // This does not copy the data from buffer but
 *                              // just annotates the 'Foo' strong-type info.
 */
template <concepts::contiguous_strong_type T>
class StrongSpan {
      using underlying_span = std::
         conditional_t<std::is_const_v<T>, std::span<const typename T::value_type>, std::span<typename T::value_type>>;

   public:
      using value_type = typename underlying_span::value_type;
      using size_type = typename underlying_span::size_type;
      using iterator = typename underlying_span::iterator;
      using pointer = typename underlying_span::pointer;
      using const_pointer = typename underlying_span::const_pointer;

      StrongSpan() = default;

      explicit StrongSpan(underlying_span span) : m_span(span) {}

      StrongSpan(T& strong) : m_span(strong) {}

      // Allows implicit conversion from `StrongSpan<T>` to `StrongSpan<const T>`.
      // Note that this is not bi-directional. Conversion from `StrongSpan<const T>`
      // to `StrongSpan<T>` is not allowed.
      //
      // TODO: Technically, we should be able to phrase this with a `requires std::is_const_v<T>`
      //       instead of the `std::enable_if` constructions. clang-tidy (14 or 15) doesn't seem
      //       to pick up on that (yet?). As a result, for a non-const T it assumes this to be
      //       a declaration of an ordinary copy constructor. The existance of a copy constructor
      //       is interpreted as "not cheap to copy", setting off the `performance-unnecessary-value-param` check.
      //       See also: https://github.com/randombit/botan/issues/3591
      template <concepts::contiguous_strong_type T2,
                typename = std::enable_if_t<std::is_same_v<T2, std::remove_const_t<T>>>>
      StrongSpan(const StrongSpan<T2>& other) : m_span(other.get()) {}

      StrongSpan(const StrongSpan& other) = default;

      ~StrongSpan() = default;

      /**
       * @returns the underlying std::span without any type constraints
       */
      underlying_span get() const { return m_span; }

      /**
       * @returns the underlying std::span without any type constraints
       */
      underlying_span get() { return m_span; }

      decltype(auto) data() noexcept(noexcept(this->m_span.data())) { return this->m_span.data(); }

      decltype(auto) data() const noexcept(noexcept(this->m_span.data())) { return this->m_span.data(); }

      decltype(auto) size() const noexcept(noexcept(this->m_span.size())) { return this->m_span.size(); }

      bool empty() const noexcept(noexcept(this->m_span.empty())) { return this->m_span.empty(); }

      decltype(auto) begin() noexcept(noexcept(this->m_span.begin())) { return this->m_span.begin(); }

      decltype(auto) begin() const noexcept(noexcept(this->m_span.begin())) { return this->m_span.begin(); }

      decltype(auto) end() noexcept(noexcept(this->m_span.end())) { return this->m_span.end(); }

      decltype(auto) end() const noexcept(noexcept(this->m_span.end())) { return this->m_span.end(); }

      decltype(auto) operator[](typename underlying_span::size_type i) const noexcept { return this->m_span[i]; }

   private:
      underlying_span m_span;
};

}  // namespace Botan

namespace Botan {

/**
* Return a shared reference to a global PRNG instance provided by the
* operating system. For instance might be instantiated by /dev/urandom
* or CryptGenRandom.
*/
BOTAN_PUBLIC_API(2, 0) RandomNumberGenerator& system_rng();

/*
* Instantiable reference to the system RNG.
*/
class BOTAN_PUBLIC_API(2, 0) System_RNG final : public RandomNumberGenerator {
   public:
      std::string name() const override { return system_rng().name(); }

      bool is_seeded() const override { return system_rng().is_seeded(); }

      bool accepts_input() const override { return system_rng().accepts_input(); }

      void clear() override { system_rng().clear(); }

   protected:
      void fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) override {
         system_rng().randomize_with_input(out, in);
      }
};

}  // namespace Botan

namespace Botan {

/*
* Get information describing the version
*/

/**
* Get a human-readable string identifying the version of Botan.
* No particular format should be assumed.
* @return version string
*/
BOTAN_PUBLIC_API(2, 0) std::string version_string();

/**
* Same as version_string() except returning a pointer to a statically
* allocated string.
* @return version string
*/
BOTAN_PUBLIC_API(2, 0) const char* version_cstr();

/**
* Return a version string of the form "MAJOR.MINOR.PATCH" where
* each of the values is an integer.
*/
BOTAN_PUBLIC_API(2, 4) std::string short_version_string();

/**
* Same as version_short_string except returning a pointer to the string.
*/
BOTAN_PUBLIC_API(2, 4) const char* short_version_cstr();

/**
* Return the date this version of botan was released, in an integer of
* the form YYYYMMDD. For instance a version released on May 21, 2013
* would return the integer 20130521. If the currently running version
* is not an official release, this function will return 0 instead.
*
* @return release date, or zero if unreleased
*/
BOTAN_PUBLIC_API(2, 0) uint32_t version_datestamp();

/**
* Get the major version number.
* @return major version number
*/
BOTAN_PUBLIC_API(2, 0) uint32_t version_major();

/**
* Get the minor version number.
* @return minor version number
*/
BOTAN_PUBLIC_API(2, 0) uint32_t version_minor();

/**
* Get the patch number.
* @return patch number
*/
BOTAN_PUBLIC_API(2, 0) uint32_t version_patch();

/**
* Usable for checking that the DLL version loaded at runtime exactly
* matches the compile-time version. Call using BOTAN_VERSION_* macro
* values. Returns the empty string if an exact match, otherwise an
* appropriate message. Added with 1.11.26.
*/
BOTAN_PUBLIC_API(2, 0) std::string runtime_version_check(uint32_t major, uint32_t minor, uint32_t patch);

/*
* Macros for compile-time version checks
*/
#define BOTAN_VERSION_CODE_FOR(a, b, c) ((a << 16) | (b << 8) | (c))

/**
* Compare using BOTAN_VERSION_CODE_FOR, as in
*  # if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,8,0)
*  #    error "Botan version too old"
*  # endif
*/
#define BOTAN_VERSION_CODE BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH)

}  // namespace Botan

#endif // BOTAN_AMALGAMATION_H_
