/*
* Botan 3.4.0 Amalgamation
* (C) 1999-2023 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../include/botan_all.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <functional>
#include <iosfwd>
#include <istream>
#include <locale>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <variant>
#include <vector>



namespace Botan {

template <concepts::contiguous_container T = std::vector<uint8_t>>
inline T to_byte_vector(std::string_view s) {
   return T(s.cbegin(), s.cend());
}

inline std::string to_string(std::span<const uint8_t> bytes) {
   return std::string(bytes.begin(), bytes.end());
}

/**
 * Reduce the values of @p keys into an accumulator initialized with @p acc using
 * the reducer function @p reducer.
 *
 * The @p reducer is a function taking the accumulator and a single key to return the
 * new accumulator. Keys are consecutively reduced into the accumulator.
 *
 * @return the accumulator containing the reduction of @p keys
 */
template <typename RetT, typename KeyT, typename ReducerT>
RetT reduce(const std::vector<KeyT>& keys, RetT acc, ReducerT reducer)
   requires std::is_convertible_v<ReducerT, std::function<RetT(RetT, const KeyT&)>>
{
   for(const KeyT& key : keys) {
      acc = reducer(std::move(acc), key);
   }
   return acc;
}

/**
* Return the keys of a map as a std::set
*/
template <typename K, typename V>
std::set<K> map_keys_as_set(const std::map<K, V>& kv) {
   std::set<K> s;
   for(auto&& i : kv) {
      s.insert(i.first);
   }
   return s;
}

/**
* Return the keys of a multimap as a std::set
*/
template <typename K, typename V>
std::set<K> map_keys_as_set(const std::multimap<K, V>& kv) {
   std::set<K> s;
   for(auto&& i : kv) {
      s.insert(i.first);
   }
   return s;
}

/*
* Searching through a std::map
* @param mapping the map to search
* @param key is what to look for
* @param null_result is the value to return if key is not in mapping
* @return mapping[key] or null_result
*/
template <typename K, typename V>
inline V search_map(const std::map<K, V>& mapping, const K& key, const V& null_result = V()) {
   auto i = mapping.find(key);
   if(i == mapping.end()) {
      return null_result;
   }
   return i->second;
}

template <typename K, typename V, typename R>
inline R search_map(const std::map<K, V>& mapping, const K& key, const R& null_result, const R& found_result) {
   auto i = mapping.find(key);
   if(i == mapping.end()) {
      return null_result;
   }
   return found_result;
}

/*
* Insert a key/value pair into a multimap
*/
template <typename K, typename V>
void multimap_insert(std::multimap<K, V>& multimap, const K& key, const V& value) {
   multimap.insert(std::make_pair(key, value));
}

/**
* Existence check for values
*/
template <typename T, typename OT>
bool value_exists(const std::vector<T>& vec, const OT& val) {
   for(size_t i = 0; i != vec.size(); ++i) {
      if(vec[i] == val) {
         return true;
      }
   }
   return false;
}

template <typename T, typename Pred>
void map_remove_if(Pred pred, T& assoc) {
   auto i = assoc.begin();
   while(i != assoc.end()) {
      if(pred(i->first)) {
         assoc.erase(i++);
      } else {
         i++;
      }
   }
}

/**
 * Helper class to ease unmarshalling of concatenated fixed-length values
 */
class BufferSlicer final {
   public:
      BufferSlicer(std::span<const uint8_t> buffer) : m_remaining(buffer) {}

      template <concepts::contiguous_container ContainerT>
      auto copy(const size_t count) {
         const auto result = take(count);
         return ContainerT(result.begin(), result.end());
      }

      auto copy_as_vector(const size_t count) { return copy<std::vector<uint8_t>>(count); }

      auto copy_as_secure_vector(const size_t count) { return copy<secure_vector<uint8_t>>(count); }

      std::span<const uint8_t> take(const size_t count) {
         BOTAN_STATE_CHECK(remaining() >= count);
         auto result = m_remaining.first(count);
         m_remaining = m_remaining.subspan(count);
         return result;
      }

      template <size_t count>
      std::span<const uint8_t, count> take() {
         BOTAN_STATE_CHECK(remaining() >= count);
         auto result = m_remaining.first<count>();
         m_remaining = m_remaining.subspan(count);
         return result;
      }

      template <concepts::contiguous_strong_type T>
      StrongSpan<const T> take(const size_t count) {
         return StrongSpan<const T>(take(count));
      }

      uint8_t take_byte() { return take(1)[0]; }

      void copy_into(std::span<uint8_t> sink) {
         const auto data = take(sink.size());
         std::copy(data.begin(), data.end(), sink.begin());
      }

      void skip(const size_t count) { take(count); }

      size_t remaining() const { return m_remaining.size(); }

      bool empty() const { return m_remaining.empty(); }

   private:
      std::span<const uint8_t> m_remaining;
};

/**
 * @brief Helper class to ease in-place marshalling of concatenated fixed-length
 *        values.
 *
 * The size of the final buffer must be known from the start, reallocations are
 * not performed.
 */
class BufferStuffer {
   public:
      constexpr BufferStuffer(std::span<uint8_t> buffer) : m_buffer(buffer) {}

      /**
       * @returns a span for the next @p bytes bytes in the concatenated buffer.
       *          Checks that the buffer is not exceded.
       */
      constexpr std::span<uint8_t> next(size_t bytes) {
         BOTAN_STATE_CHECK(m_buffer.size() >= bytes);

         auto result = m_buffer.first(bytes);
         m_buffer = m_buffer.subspan(bytes);
         return result;
      }

      template <size_t bytes>
      constexpr std::span<uint8_t, bytes> next() {
         BOTAN_STATE_CHECK(m_buffer.size() >= bytes);

         auto result = m_buffer.first<bytes>();
         m_buffer = m_buffer.subspan(bytes);
         return result;
      }

      template <concepts::contiguous_strong_type StrongT>
      StrongSpan<StrongT> next(size_t bytes) {
         return StrongSpan<StrongT>(next(bytes));
      }

      /**
       * @returns a reference to the next single byte in the buffer
       */
      constexpr uint8_t& next_byte() { return next(1)[0]; }

      constexpr void append(std::span<const uint8_t> buffer) {
         auto sink = next(buffer.size());
         std::copy(buffer.begin(), buffer.end(), sink.begin());
      }

      constexpr void append(uint8_t b, size_t repeat = 1) {
         auto sink = next(repeat);
         std::fill(sink.begin(), sink.end(), b);
      }

      constexpr bool full() const { return m_buffer.empty(); }

      constexpr size_t remaining_capacity() const { return m_buffer.size(); }

   private:
      std::span<uint8_t> m_buffer;
};

/**
 * Concatenate an arbitrary number of buffers.
 * @return the concatenation of \p buffers as the container type of the first buffer
 */
template <typename... Ts>
decltype(auto) concat(Ts&&... buffers) {
   static_assert(sizeof...(buffers) > 0, "concat requires at least one buffer");

   using result_t = std::remove_cvref_t<std::tuple_element_t<0, std::tuple<Ts...>>>;
   result_t result;
   result.reserve((buffers.size() + ...));
   (result.insert(result.end(), buffers.begin(), buffers.end()), ...);
   return result;
}

/**
 * Concatenate an arbitrary number of buffers and define the output buffer
 * type as a mandatory template parameter.
 * @return the concatenation of \p buffers as the user-defined container type
 */
template <typename ResultT, typename... Ts>
ResultT concat_as(Ts&&... buffers) {
   return concat(ResultT(), std::forward<Ts>(buffers)...);
}

template <typename... Alts, typename... Ts>
constexpr bool holds_any_of(const std::variant<Ts...>& v) noexcept {
   return (std::holds_alternative<Alts>(v) || ...);
}

template <typename GeneralVariantT, typename SpecialT>
constexpr bool is_generalizable_to(const SpecialT&) noexcept {
   return std::is_constructible_v<GeneralVariantT, SpecialT>;
}

template <typename GeneralVariantT, typename... SpecialTs>
constexpr bool is_generalizable_to(const std::variant<SpecialTs...>&) noexcept {
   return (std::is_constructible_v<GeneralVariantT, SpecialTs> && ...);
}

/**
 * @brief Converts a given variant into another variant-ish whose type states
 *        are a super set of the given variant.
 *
 * This is useful to convert restricted variant types into more general
 * variants types.
 */
template <typename GeneralVariantT, typename SpecialT>
constexpr GeneralVariantT generalize_to(SpecialT&& specific) noexcept
   requires(std::is_constructible_v<GeneralVariantT, std::decay_t<SpecialT>>)
{
   return std::forward<SpecialT>(specific);
}

/**
 * @brief Converts a given variant into another variant-ish whose type states
 *        are a super set of the given variant.
 *
 * This is useful to convert restricted variant types into more general
 * variants types.
 */
template <typename GeneralVariantT, typename... SpecialTs>
constexpr GeneralVariantT generalize_to(std::variant<SpecialTs...> specific) noexcept {
   static_assert(
      is_generalizable_to<GeneralVariantT>(specific),
      "Desired general type must be implicitly constructible by all types of the specialized std::variant<>");
   return std::visit([](auto s) -> GeneralVariantT { return s; }, std::move(specific));
}

// This is a helper utility to emulate pattern matching with std::visit.
// See https://en.cppreference.com/w/cpp/utility/variant/visit for more info.
template <class... Ts>
struct overloaded : Ts... {
      using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

/**
 * @brief Helper class to create a RAII-style cleanup callback
 *
 * Ensures that the cleanup callback given in the object's constructor is called
 * when the object is destroyed. Use this to ensure some cleanup code runs when
 * leaving the current scope.
 */
template <std::invocable FunT>
class scoped_cleanup {
   public:
      explicit scoped_cleanup(FunT cleanup) : m_cleanup(std::move(cleanup)) {}

      scoped_cleanup(const scoped_cleanup&) = delete;
      scoped_cleanup& operator=(const scoped_cleanup&) = delete;
      scoped_cleanup(scoped_cleanup&&) = delete;
      scoped_cleanup& operator=(scoped_cleanup&&) = delete;

      ~scoped_cleanup() {
         if(m_cleanup.has_value()) {
            m_cleanup.value()();
         }
      }

      /**
       * Disengage the cleanup callback, i.e., prevent it from being called
       */
      void disengage() { m_cleanup.reset(); }

   private:
      std::optional<FunT> m_cleanup;
};

}  // namespace Botan


namespace Botan {

/**
 * Defines the strategy for handling the final block of input data in the
 * handle_unaligned_data() method of the AlignmentBuffer<>.
 *
 * - is_not_special:   the final block is treated like any other block
 * - must_be_deferred: the final block is not emitted while bulk processing (typically add_data())
 *                     but is deferred until manually consumed (typically final_result())
 *
 * The AlignmentBuffer<> assumes data to be "the final block" if no further
 * input data is available in the BufferSlicer<>. This might result in some
 * performance overhead when using the must_be_deferred strategy.
 */
enum class AlignmentBufferFinalBlock : size_t {
   is_not_special = 0,
   must_be_deferred = 1,
};

/**
 * @brief Alignment buffer helper
 *
 * Many algorithms have an intrinsic block size in which they consume input
 * data. When streaming arbitrary data chunks to such algorithms we must store
 * some data intermittently to honor the algorithm's alignment requirements.
 *
 * This helper encapsulates such an alignment buffer. The API of this class is
 * designed to minimize user errors in the algorithm implementations. Therefore,
 * it is strongly opinionated on its use case. Don't try to use it for anything
 * but the described circumstance.
 *
 * @tparam T                     the element type of the internal buffer
 * @tparam BLOCK_SIZE            the buffer size to use for the alignment buffer
 * @tparam FINAL_BLOCK_STRATEGY  defines whether the final input data block is
 *                               retained in handle_unaligned_data() and must be
 *                               manually consumed
 */
template <typename T,
          size_t BLOCK_SIZE,
          AlignmentBufferFinalBlock FINAL_BLOCK_STRATEGY = AlignmentBufferFinalBlock::is_not_special>
   requires(BLOCK_SIZE > 0)
class AlignmentBuffer {
   public:
      AlignmentBuffer() : m_position(0) {}

      ~AlignmentBuffer() { secure_scrub_memory(m_buffer.data(), m_buffer.size()); }

      AlignmentBuffer(const AlignmentBuffer& other) = default;
      AlignmentBuffer(AlignmentBuffer&& other) noexcept = default;
      AlignmentBuffer& operator=(const AlignmentBuffer& other) = default;
      AlignmentBuffer& operator=(AlignmentBuffer&& other) noexcept = default;

      void clear() {
         clear_mem(m_buffer.data(), m_buffer.size());
         m_position = 0;
      }

      /**
       * Fills the currently unused bytes of the buffer with zero bytes
       */
      void fill_up_with_zeros() {
         if(!ready_to_consume()) {
            clear_mem(&m_buffer[m_position], elements_until_alignment());
            m_position = m_buffer.size();
         }
      }

      /**
       * Appends the provided @p elements to the buffer. The user has to make
       * sure that @p elements fits in the remaining capacity of the buffer.
       */
      void append(std::span<const T> elements) {
         BOTAN_ASSERT_NOMSG(elements.size() <= elements_until_alignment());
         std::copy(elements.begin(), elements.end(), m_buffer.begin() + m_position);
         m_position += elements.size();
      }

      /**
       * Allows direct modification of the first @p elements in the buffer.
       * This is a low-level accessor that neither takes the buffer's current
       * capacity into account nor does it change the internal cursor.
       * Beware not to overwrite unconsumed bytes.
       */
      std::span<T> directly_modify_first(size_t elements) {
         BOTAN_ASSERT_NOMSG(size() >= elements);
         return std::span(m_buffer).first(elements);
      }

      /**
       * Allows direct modification of the last @p elements in the buffer.
       * This is a low-level accessor that neither takes the buffer's current
       * capacity into account nor does it change the internal cursor.
       * Beware not to overwrite unconsumed bytes.
       */
      std::span<T> directly_modify_last(size_t elements) {
         BOTAN_ASSERT_NOMSG(size() >= elements);
         return std::span(m_buffer).last(elements);
      }

      /**
       * Once the buffer reached alignment, this can be used to consume as many
       * input bytes from the given @p slider as possible. The output always
       * contains data elements that are a multiple of the intrinsic block size.
       *
       * @returns a view onto the aligned data from @p slicer and the number of
       *          full blocks that are represented by this view.
       */
      [[nodiscard]] std::tuple<std::span<const uint8_t>, size_t> aligned_data_to_process(BufferSlicer& slicer) const {
         BOTAN_ASSERT_NOMSG(in_alignment());

         // When the final block is to be deferred, the last block must not be
         // selected for processing if there is no (unaligned) extra input data.
         const size_t defer = (defers_final_block()) ? 1 : 0;
         const size_t full_blocks_to_process = (slicer.remaining() - defer) / m_buffer.size();
         return {slicer.take(full_blocks_to_process * m_buffer.size()), full_blocks_to_process};
      }

      /**
       * Once the buffer reached alignment, this can be used to consume full
       * blocks from the input data represented by @p slicer.
       *
       * @returns a view onto the next full block from @p slicer or std::nullopt
       *          if not enough data is available in @p slicer.
       */
      [[nodiscard]] std::optional<std::span<const uint8_t>> next_aligned_block_to_process(BufferSlicer& slicer) const {
         BOTAN_ASSERT_NOMSG(in_alignment());

         // When the final block is to be deferred, the last block must not be
         // selected for processing if there is no (unaligned) extra input data.
         const size_t defer = (defers_final_block()) ? 1 : 0;
         if(slicer.remaining() < m_buffer.size() + defer) {
            return std::nullopt;
         }

         return slicer.take(m_buffer.size());
      }

      /**
       * Intermittently buffers potentially unaligned data provided in @p
       * slicer. If the internal buffer already contains some elements, data is
       * appended. Once a full block is collected, it is returned to the caller
       * for processing.
       *
       * @param slicer the input data source to be (partially) consumed
       * @returns a view onto a full block once enough data was collected, or
       *          std::nullopt if no full block is available yet
       */
      [[nodiscard]] std::optional<std::span<const T>> handle_unaligned_data(BufferSlicer& slicer) {
         // When the final block is to be deferred, we would need to store and
         // hold a buffer that contains exactly one block until more data is
         // passed or it is explicitly consumed.
         const size_t defer = (defers_final_block()) ? 1 : 0;

         if(in_alignment() && slicer.remaining() >= m_buffer.size() + defer) {
            // We are currently in alignment and the passed-in data source
            // contains enough data to benefit from aligned processing.
            // Therefore, we don't copy anything into the intermittent buffer.
            return std::nullopt;
         }

         // Fill the buffer with as much input data as needed to reach alignment
         // or until the input source is depleted.
         const auto elements_to_consume = std::min(m_buffer.size() - m_position, slicer.remaining());
         append(slicer.take(elements_to_consume));

         // If we collected enough data, we push out one full block. When
         // deferring the final block is enabled, we additionally check that
         // more input data is available to continue processing a consecutive
         // block.
         if(ready_to_consume() && (!defers_final_block() || !slicer.empty())) {
            return consume();
         } else {
            return std::nullopt;
         }
      }

      /**
       * Explicitly consume the currently collected block. It is the caller's
       * responsibility to ensure that the buffer is filled fully. After
       * consumption, the buffer is cleared and ready to collect new data.
       */
      [[nodiscard]] std::span<const T> consume() {
         BOTAN_ASSERT_NOMSG(ready_to_consume());
         m_position = 0;
         return m_buffer;
      }

      /**
       * Explicitly consumes however many bytes are currently stored in the
       * buffer. After consumption, the buffer is cleared and ready to collect
       * new data.
       */
      [[nodiscard]] std::span<const T> consume_partial() {
         const auto elements = elements_in_buffer();
         m_position = 0;
         return std::span(m_buffer).first(elements);
      }

      constexpr size_t size() const { return m_buffer.size(); }

      size_t elements_in_buffer() const { return m_position; }

      size_t elements_until_alignment() const { return m_buffer.size() - m_position; }

      /**
       * @returns true if the buffer is empty (i.e. contains no unaligned data)
       */
      bool in_alignment() const { return m_position == 0; }

      /**
       * @returns true if the buffer is full (i.e. a block is ready to be consumed)
       */
      bool ready_to_consume() const { return m_position == m_buffer.size(); }

      constexpr bool defers_final_block() const {
         return FINAL_BLOCK_STRATEGY == AlignmentBufferFinalBlock::must_be_deferred;
      }

   private:
      std::array<T, BLOCK_SIZE> m_buffer;
      size_t m_position;
};

}  // namespace Botan

namespace Botan {

/**
* If top bit of arg is set, return ~0. Otherwise return 0.
*/
template <typename T>
inline constexpr T expand_top_bit(T a)
   requires(std::is_integral<T>::value)
{
   return static_cast<T>(0) - (a >> (sizeof(T) * 8 - 1));
}

/**
* If arg is zero, return ~0. Otherwise return 0
*/
template <typename T>
inline constexpr T ct_is_zero(T x)
   requires(std::is_integral<T>::value)
{
   return expand_top_bit<T>(~x & (x - 1));
}

/**
* Power of 2 test. T should be an unsigned integer type
* @param arg an integer value
* @return true iff arg is 2^n for some n > 0
*/
template <typename T>
inline constexpr bool is_power_of_2(T arg)
   requires(std::is_unsigned<T>::value)
{
   return (arg != 0) && (arg != 1) && ((arg & static_cast<T>(arg - 1)) == 0);
}

/**
* Return the index of the highest set bit
* T is an unsigned integer type
* @param n an integer value
* @return index of the highest set bit in n
*/
template <typename T>
inline constexpr size_t high_bit(T n)
   requires(std::is_unsigned<T>::value)
{
   size_t hb = 0;

   for(size_t s = 8 * sizeof(T) / 2; s > 0; s /= 2) {
      const size_t z = s * ((~ct_is_zero(n >> s)) & 1);
      hb += z;
      n >>= z;
   }

   hb += n;

   return hb;
}

/**
* Return the number of significant bytes in n
* @param n an integer value
* @return number of significant bytes in n
*/
template <typename T>
inline constexpr size_t significant_bytes(T n)
   requires(std::is_integral<T>::value)
{
   size_t b = 0;

   for(size_t s = 8 * sizeof(n) / 2; s >= 8; s /= 2) {
      const size_t z = s * (~ct_is_zero(n >> s) & 1);
      b += z / 8;
      n >>= z;
   }

   b += (n != 0);

   return b;
}

/**
* Count the trailing zero bits in n
* @param n an integer value
* @return maximum x st 2^x divides n
*/
template <typename T>
inline constexpr size_t ctz(T n)
   requires(std::is_integral<T>::value)
{
   /*
   * If n == 0 then this function will compute 8*sizeof(T)-1, so
   * initialize lb to 1 if n == 0 to produce the expected result.
   */
   size_t lb = ct_is_zero(n) & 1;

   for(size_t s = 8 * sizeof(T) / 2; s > 0; s /= 2) {
      const T mask = (static_cast<T>(1) << s) - 1;
      const size_t z = s * (ct_is_zero(n & mask) & 1);
      lb += z;
      n >>= z;
   }

   return lb;
}

template <typename T>
constexpr uint8_t ceil_log2(T x)
   requires(std::is_integral<T>::value && sizeof(T) < 32)
{
   if(x >> (sizeof(T) * 8 - 1)) {
      return sizeof(T) * 8;
   }

   uint8_t result = 0;
   T compare = 1;

   while(compare < x) {
      compare <<= 1;
      result++;
   }

   return result;
}

/**
 * Return the number of bytes necessary to contain @p bits bits.
 */
template <typename T>
inline constexpr T ceil_tobytes(T bits)
   requires(std::is_integral<T>::value)
{
   return (bits + 7) / 8;
}

// Potentially variable time ctz used for OCB
inline constexpr size_t var_ctz32(uint32_t n) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_ctz)
   if(n == 0) {
      return 32;
   }
   return __builtin_ctz(n);
#else
   return ctz<uint32_t>(n);
#endif
}

template <typename T>
inline constexpr T bit_permute_step(T x, T mask, size_t shift) {
   /*
   See https://reflectionsonsecurity.wordpress.com/2014/05/11/efficient-bit-permutation-using-delta-swaps/
   and http://programming.sirrida.de/bit_perm.html
   */
   const T swap = ((x >> shift) ^ x) & mask;
   return (x ^ swap) ^ (swap << shift);
}

template <typename T>
inline constexpr void swap_bits(T& x, T& y, T mask, size_t shift) {
   const T swap = ((x >> shift) ^ y) & mask;
   x ^= swap << shift;
   y ^= swap;
}

template <typename T>
inline constexpr T choose(T mask, T a, T b) {
   //return (mask & a) | (~mask & b);
   return (b ^ (mask & (a ^ b)));
}

template <typename T>
inline constexpr T majority(T a, T b, T c) {
   /*
   Considering each bit of a, b, c individually

   If a xor b is set, then c is the deciding vote.

   If a xor b is not set then either a and b are both set or both unset.
   In either case the value of c doesn't matter, and examining b (or a)
   allows us to determine which case we are in.
   */
   return choose(a ^ b, c, b);
}

}  // namespace Botan

namespace Botan {

/**
* Blowfish
*/
class BOTAN_TEST_API Blowfish final : public Block_Cipher_Fixed_Params<8, 1, 56> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      /**
      * Modified EKSBlowfish key schedule, used for bcrypt password hashing
      */
      void salted_set_key(const uint8_t key[],
                          size_t key_length,
                          const uint8_t salt[],
                          size_t salt_length,
                          size_t workfactor,
                          bool salt_first = false);

      void clear() override;

      std::string name() const override { return "Blowfish"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Blowfish>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      void key_expansion(const uint8_t key[], size_t key_length, const uint8_t salt[], size_t salt_length);

      void generate_sbox(secure_vector<uint32_t>& box,
                         uint32_t& L,
                         uint32_t& R,
                         const uint8_t salt[],
                         size_t salt_length,
                         size_t salt_off) const;

      secure_vector<uint32_t> m_S, m_P;
};

}  // namespace Botan

namespace Botan {

/**
* Swap a 16 bit integer
*/
inline constexpr uint16_t reverse_bytes(uint16_t x) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap16)
   return __builtin_bswap16(x);
#else
   return static_cast<uint16_t>((x << 8) | (x >> 8));
#endif
}

/**
* Swap a 32 bit integer
*
* We cannot use MSVC's _byteswap_ulong because it does not consider
* the builtin to be constexpr.
*/
inline constexpr uint32_t reverse_bytes(uint32_t x) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap32)
   return __builtin_bswap32(x);
#else
   // MSVC at least recognizes this as a bswap
   return ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) | ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24);
#endif
}

/**
* Swap a 64 bit integer
*
* We cannot use MSVC's _byteswap_uint64 because it does not consider
* the builtin to be constexpr.
*/
inline constexpr uint64_t reverse_bytes(uint64_t x) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap64)
   return __builtin_bswap64(x);
#else
   uint32_t hi = static_cast<uint32_t>(x >> 32);
   uint32_t lo = static_cast<uint32_t>(x);

   hi = reverse_bytes(hi);
   lo = reverse_bytes(lo);

   return (static_cast<uint64_t>(lo) << 32) | hi;
#endif
}

}  // namespace Botan

namespace Botan {

/**
* Struct representing a particular date and time
*/
class BOTAN_TEST_API calendar_point {
   public:
      /** The year */
      uint32_t year() const { return m_year; }

      /** The month, 1 through 12 for Jan to Dec */
      uint32_t month() const { return m_month; }

      /** The day of the month, 1 through 31 (or 28 or 30 based on month */
      uint32_t day() const { return m_day; }

      /** Hour in 24-hour form, 0 to 23 */
      uint32_t hour() const { return m_hour; }

      /** Minutes in the hour, 0 to 60 */
      uint32_t minutes() const { return m_minutes; }

      /** Seconds in the minute, 0 to 60, but might be slightly
      larger to deal with leap seconds on some systems
      */
      uint32_t seconds() const { return m_seconds; }

      /**
      * Initialize a calendar_point
      * @param y the year
      * @param mon the month
      * @param d the day
      * @param h the hour
      * @param min the minute
      * @param sec the second
      */
      calendar_point(uint32_t y, uint32_t mon, uint32_t d, uint32_t h, uint32_t min, uint32_t sec) :
            m_year(y), m_month(mon), m_day(d), m_hour(h), m_minutes(min), m_seconds(sec) {}

      /**
      * Convert a time_point to a calendar_point
      * @param time_point a time point from the system clock
      */
      calendar_point(const std::chrono::system_clock::time_point& time_point);

      /**
      * Returns an STL timepoint object
      */
      std::chrono::system_clock::time_point to_std_timepoint() const;

      /**
      * Returns a human readable string of the struct's components.
      * Formatting might change over time. Currently it is RFC339 'iso-date-time'.
      */
      std::string to_string() const;

   private:
      uint32_t m_year;
      uint32_t m_month;
      uint32_t m_day;
      uint32_t m_hour;
      uint32_t m_minutes;
      uint32_t m_seconds;
};

}  // namespace Botan

namespace Botan {

/**
* Convert a sequence of UCS-2 (big endian) characters to a UTF-8 string
* This is used for ASN.1 BMPString type
* @param ucs2 the sequence of UCS-2 characters
* @param len length of ucs2 in bytes, must be a multiple of 2
*/
BOTAN_TEST_API std::string ucs2_to_utf8(const uint8_t ucs2[], size_t len);

/**
* Convert a sequence of UCS-4 (big endian) characters to a UTF-8 string
* This is used for ASN.1 UniversalString type
* @param ucs4 the sequence of UCS-4 characters
* @param len length of ucs4 in bytes, must be a multiple of 4
*/
BOTAN_TEST_API std::string ucs4_to_utf8(const uint8_t ucs4[], size_t len);

BOTAN_TEST_API std::string latin1_to_utf8(const uint8_t latin1[], size_t len);

/**
* Return a string containing 'c', quoted and possibly escaped
*
* This is used when creating an error message nothing an invalid character
* in some codex (for example during hex decoding)
*
* Currently this function escapes tab, newlines and carriage return
* as "\t", "\n", and "\r", and also escapes characters > 0x7F as
* "\xHH" where HH is the hex code.
*/
std::string format_char_for_display(char c);

}  // namespace Botan

namespace Botan {

/**
* Perform encoding using the base provided
* @param base object giving access to the encodings specifications
* @param output an array of at least base.encode_max_output bytes
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
template <class Base>
size_t base_encode(
   Base&& base, char output[], const uint8_t input[], size_t input_length, size_t& input_consumed, bool final_inputs) {
   input_consumed = 0;

   const size_t encoding_bytes_in = base.encoding_bytes_in();
   const size_t encoding_bytes_out = base.encoding_bytes_out();

   size_t input_remaining = input_length;
   size_t output_produced = 0;

   while(input_remaining >= encoding_bytes_in) {
      base.encode(output + output_produced, input + input_consumed);

      input_consumed += encoding_bytes_in;
      output_produced += encoding_bytes_out;
      input_remaining -= encoding_bytes_in;
   }

   if(final_inputs && input_remaining) {
      std::vector<uint8_t> remainder(encoding_bytes_in, 0);
      for(size_t i = 0; i != input_remaining; ++i) {
         remainder[i] = input[input_consumed + i];
      }

      base.encode(output + output_produced, remainder.data());

      const size_t bits_consumed = base.bits_consumed();
      const size_t remaining_bits_before_padding = base.remaining_bits_before_padding();

      size_t empty_bits = 8 * (encoding_bytes_in - input_remaining);
      size_t index = output_produced + encoding_bytes_out - 1;
      while(empty_bits >= remaining_bits_before_padding) {
         output[index--] = '=';
         empty_bits -= bits_consumed;
      }

      input_consumed += input_remaining;
      output_produced += encoding_bytes_out;
   }

   return output_produced;
}

template <typename Base>
std::string base_encode_to_string(Base&& base, const uint8_t input[], size_t input_length) {
   const size_t output_length = base.encode_max_output(input_length);
   std::string output(output_length, 0);

   size_t consumed = 0;
   size_t produced = 0;

   if(output_length > 0) {
      produced = base_encode(base, &output.front(), input, input_length, consumed, true);
   }

   BOTAN_ASSERT_EQUAL(consumed, input_length, "Consumed the entire input");
   BOTAN_ASSERT_EQUAL(produced, output.size(), "Produced expected size");

   return output;
}

/**
* Perform decoding using the base provided
* @param base object giving access to the encodings specifications
* @param output an array of at least Base::decode_max_output bytes
* @param input some base input
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
template <typename Base>
size_t base_decode(Base&& base,
                   uint8_t output[],
                   const char input[],
                   size_t input_length,
                   size_t& input_consumed,
                   bool final_inputs,
                   bool ignore_ws = true) {
   const size_t decoding_bytes_in = base.decoding_bytes_in();
   const size_t decoding_bytes_out = base.decoding_bytes_out();

   uint8_t* out_ptr = output;
   std::vector<uint8_t> decode_buf(decoding_bytes_in, 0);
   size_t decode_buf_pos = 0;
   size_t final_truncate = 0;

   clear_mem(output, base.decode_max_output(input_length));

   for(size_t i = 0; i != input_length; ++i) {
      const uint8_t bin = base.lookup_binary_value(input[i]);

      // This call might throw Invalid_Argument
      if(base.check_bad_char(bin, input[i], ignore_ws)) {
         decode_buf[decode_buf_pos] = bin;
         ++decode_buf_pos;
      }

      /*
      * If we're at the end of the input, pad with 0s and truncate
      */
      if(final_inputs && (i == input_length - 1)) {
         if(decode_buf_pos) {
            for(size_t j = decode_buf_pos; j < decoding_bytes_in; ++j) {
               decode_buf[j] = 0;
            }

            final_truncate = decoding_bytes_in - decode_buf_pos;
            decode_buf_pos = decoding_bytes_in;
         }
      }

      if(decode_buf_pos == decoding_bytes_in) {
         base.decode(out_ptr, decode_buf.data());

         out_ptr += decoding_bytes_out;
         decode_buf_pos = 0;
         input_consumed = i + 1;
      }
   }

   while(input_consumed < input_length && base.lookup_binary_value(input[input_consumed]) == 0x80) {
      ++input_consumed;
   }

   size_t written = (out_ptr - output) - base.bytes_to_remove(final_truncate);

   return written;
}

template <typename Base>
size_t base_decode_full(Base&& base, uint8_t output[], const char input[], size_t input_length, bool ignore_ws) {
   size_t consumed = 0;
   const size_t written = base_decode(base, output, input, input_length, consumed, true, ignore_ws);

   if(consumed != input_length) {
      throw Invalid_Argument(base.name() + " decoding failed, input did not have full bytes");
   }

   return written;
}

template <typename Vector, typename Base>
Vector base_decode_to_vec(Base&& base, const char input[], size_t input_length, bool ignore_ws) {
   const size_t output_length = base.decode_max_output(input_length);
   Vector bin(output_length);

   const size_t written = base_decode_full(base, bin.data(), input, input_length, ignore_ws);

   bin.resize(written);
   return bin;
}

}  // namespace Botan

namespace Botan {

/**
* A class handling runtime CPU feature detection. It is limited to
* just the features necessary to implement CPU specific code in Botan,
* rather than being a general purpose utility.
*
* This class supports:
*
*  - x86 features using CPUID. x86 is also the only processor with
*    accurate cache line detection currently.
*
*  - PowerPC AltiVec detection on Linux, NetBSD, OpenBSD, and macOS
*
*  - ARM NEON and crypto extensions detection. On Linux and Android
*    systems which support getauxval, that is used to access CPU
*    feature information. Otherwise a relatively portable but
*    thread-unsafe mechanism involving executing probe functions which
*    catching SIGILL signal is used.
*/
class BOTAN_TEST_API CPUID final {
   public:
      /**
      * Probe the CPU and see what extensions are supported
      */
      static void initialize();

      /**
      * Return true if a 4x32 SIMD instruction set is available
      * (SSE2, NEON, or Altivec/VMX)
      */
      static bool has_simd_32();

      /**
      * Return a possibly empty string containing list of known CPU
      * extensions. Each name will be seperated by a space, and the ordering
      * will be arbitrary. This list only contains values that are useful to
      * Botan (for example FMA instructions are not checked).
      *
      * Example outputs "sse2 ssse3 rdtsc", "neon arm_aes", "altivec"
      */
      static std::string to_string();

      static bool is_little_endian() {
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
         return true;
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
         return false;
#else
         return !has_cpuid_bit(CPUID_IS_BIG_ENDIAN_BIT);
#endif
      }

      static bool is_big_endian() {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
         return true;
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
         return false;
#else
         return has_cpuid_bit(CPUID_IS_BIG_ENDIAN_BIT);
#endif
      }

      enum CPUID_bits : uint32_t {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         // These values have no relation to cpuid bitfields

         // SIMD instruction sets
         CPUID_SSE2_BIT = (1U << 0),
         CPUID_SSSE3_BIT = (1U << 1),
         CPUID_AVX2_BIT = (1U << 2),
         CPUID_AVX512_BIT = (1U << 3),

         // Misc useful instructions
         CPUID_RDTSC_BIT = (1U << 10),
         CPUID_ADX_BIT = (1U << 11),
         CPUID_BMI_BIT = (1U << 12),

         // Crypto-specific ISAs
         CPUID_AESNI_BIT = (1U << 16),
         CPUID_CLMUL_BIT = (1U << 17),
         CPUID_RDRAND_BIT = (1U << 18),
         CPUID_RDSEED_BIT = (1U << 19),
         CPUID_SHA_BIT = (1U << 20),
         CPUID_AVX512_AES_BIT = (1U << 21),
         CPUID_AVX512_CLMUL_BIT = (1U << 22),
#endif

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         CPUID_ALTIVEC_BIT = (1U << 0),
         CPUID_POWER_CRYPTO_BIT = (1U << 1),
         CPUID_DARN_BIT = (1U << 2),
#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         CPUID_ARM_NEON_BIT = (1U << 0),
         CPUID_ARM_SVE_BIT = (1U << 1),
         CPUID_ARM_AES_BIT = (1U << 16),
         CPUID_ARM_PMULL_BIT = (1U << 17),
         CPUID_ARM_SHA1_BIT = (1U << 18),
         CPUID_ARM_SHA2_BIT = (1U << 19),
         CPUID_ARM_SHA3_BIT = (1U << 20),
         CPUID_ARM_SHA2_512_BIT = (1U << 21),
         CPUID_ARM_SM3_BIT = (1U << 22),
         CPUID_ARM_SM4_BIT = (1U << 23),
#endif

         CPUID_IS_BIG_ENDIAN_BIT = (1U << 30),
         CPUID_INITIALIZED_BIT = (1U << 31)
      };

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
      /**
      * Check if the processor supports AltiVec/VMX
      */
      static bool has_altivec() { return has_cpuid_bit(CPUID_ALTIVEC_BIT); }

      /**
      * Check if the processor supports POWER8 crypto extensions
      */
      static bool has_power_crypto() { return has_altivec() && has_cpuid_bit(CPUID_POWER_CRYPTO_BIT); }

      /**
      * Check if the processor supports POWER9 DARN RNG
      */
      static bool has_darn_rng() { return has_cpuid_bit(CPUID_DARN_BIT); }

#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
      /**
      * Check if the processor supports NEON SIMD
      */
      static bool has_neon() { return has_cpuid_bit(CPUID_ARM_NEON_BIT); }

      /**
      * Check if the processor supports ARMv8 SVE
      */
      static bool has_arm_sve() { return has_cpuid_bit(CPUID_ARM_SVE_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA1
      */
      static bool has_arm_sha1() { return has_neon() && has_cpuid_bit(CPUID_ARM_SHA1_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA2
      */
      static bool has_arm_sha2() { return has_neon() && has_cpuid_bit(CPUID_ARM_SHA2_BIT); }

      /**
      * Check if the processor supports ARMv8 AES
      */
      static bool has_arm_aes() { return has_neon() && has_cpuid_bit(CPUID_ARM_AES_BIT); }

      /**
      * Check if the processor supports ARMv8 PMULL
      */
      static bool has_arm_pmull() { return has_neon() && has_cpuid_bit(CPUID_ARM_PMULL_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA-512
      */
      static bool has_arm_sha2_512() { return has_neon() && has_cpuid_bit(CPUID_ARM_SHA2_512_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA-3
      */
      static bool has_arm_sha3() { return has_neon() && has_cpuid_bit(CPUID_ARM_SHA3_BIT); }

      /**
      * Check if the processor supports ARMv8 SM3
      */
      static bool has_arm_sm3() { return has_neon() && has_cpuid_bit(CPUID_ARM_SM3_BIT); }

      /**
      * Check if the processor supports ARMv8 SM4
      */
      static bool has_arm_sm4() { return has_neon() && has_cpuid_bit(CPUID_ARM_SM4_BIT); }

#endif

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

      /**
      * Check if the processor supports RDTSC
      */
      static bool has_rdtsc() { return has_cpuid_bit(CPUID_RDTSC_BIT); }

      /**
      * Check if the processor supports SSE2
      */
      static bool has_sse2() { return has_cpuid_bit(CPUID_SSE2_BIT); }

      /**
      * Check if the processor supports SSSE3
      */
      static bool has_ssse3() { return has_sse2() && has_cpuid_bit(CPUID_SSSE3_BIT); }

      /**
      * Check if the processor supports AVX2
      */
      static bool has_avx2() { return has_cpuid_bit(CPUID_AVX2_BIT); }

      /**
      * Check if the processor supports our AVX-512 minimum profile
      *
      * Namely AVX-512 F, DQ, BW, VL, IFMA, VBMI, VBMI2, BITALG
      */
      static bool has_avx512() { return has_cpuid_bit(CPUID_AVX512_BIT); }

      /**
      * Check if the processor supports AVX-512 AES (VAES)
      */
      static bool has_avx512_aes() { return has_avx512() && has_cpuid_bit(CPUID_AVX512_AES_BIT); }

      /**
      * Check if the processor supports AVX-512 VPCLMULQDQ
      */
      static bool has_avx512_clmul() { return has_avx512() && has_cpuid_bit(CPUID_AVX512_CLMUL_BIT); }

      /**
      * Check if the processor supports BMI2 (and BMI1)
      */
      static bool has_bmi2() { return has_cpuid_bit(CPUID_BMI_BIT); }

      /**
      * Check if the processor supports AES-NI
      */
      static bool has_aes_ni() { return has_ssse3() && has_cpuid_bit(CPUID_AESNI_BIT); }

      /**
      * Check if the processor supports CLMUL
      */
      static bool has_clmul() { return has_ssse3() && has_cpuid_bit(CPUID_CLMUL_BIT); }

      /**
      * Check if the processor supports Intel SHA extension
      */
      static bool has_intel_sha() { return has_sse2() && has_cpuid_bit(CPUID_SHA_BIT); }

      /**
      * Check if the processor supports ADX extension
      */
      static bool has_adx() { return has_cpuid_bit(CPUID_ADX_BIT); }

      /**
      * Check if the processor supports RDRAND
      */
      static bool has_rdrand() { return has_cpuid_bit(CPUID_RDRAND_BIT); }

      /**
      * Check if the processor supports RDSEED
      */
      static bool has_rdseed() { return has_cpuid_bit(CPUID_RDSEED_BIT); }
#endif

      /**
      * Check if the processor supports byte-level vector permutes
      * (SSSE3, NEON, Altivec)
      */
      static bool has_vperm() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_ssse3();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_neon();
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         return has_altivec();
#else
         return false;
#endif
      }

      /**
      * Check if the processor supports hardware AES instructions
      */
      static bool has_hw_aes() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_aes_ni();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_arm_aes();
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         return has_power_crypto();
#else
         return false;
#endif
      }

      /**
      * Check if the processor supports carryless multiply
      * (CLMUL, PMULL)
      */
      static bool has_carryless_multiply() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_clmul();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_arm_pmull();
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
         return has_power_crypto();
#else
         return false;
#endif
      }

      /*
      * Clear a CPUID bit
      * Call CPUID::initialize to reset
      *
      * This is only exposed for testing, don't use unless you know
      * what you are doing.
      */
      static void clear_cpuid_bit(CPUID_bits bit) { state().clear_cpuid_bit(static_cast<uint32_t>(bit)); }

      /*
      * Don't call this function, use CPUID::has_xxx above
      * It is only exposed for the tests.
      */
      static bool has_cpuid_bit(CPUID_bits elem) {
         const uint32_t elem32 = static_cast<uint32_t>(elem);
         return state().has_bit(elem32);
      }

      static std::vector<CPUID::CPUID_bits> bit_from_string(std::string_view tok);

   private:
      struct CPUID_Data {
         public:
            CPUID_Data();

            CPUID_Data(const CPUID_Data& other) = default;
            CPUID_Data& operator=(const CPUID_Data& other) = default;

            void clear_cpuid_bit(uint32_t bit) { m_processor_features &= ~bit; }

            bool has_bit(uint32_t bit) const { return (m_processor_features & bit) == bit; }

         private:
#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY) || defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY) || \
   defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

            static uint32_t detect_cpu_features();

#endif
            uint32_t m_processor_features;
      };

      static CPUID_Data& state() {
         static CPUID::CPUID_Data g_cpuid;
         return g_cpuid;
      }
};

}  // namespace Botan

#if defined(BOTAN_HAS_VALGRIND)
   #include <valgrind/memcheck.h>
#endif

namespace Botan::CT {

/**
* Use valgrind to mark the contents of memory as being undefined.
* Valgrind will accept operations which manipulate undefined values,
* but will warn if an undefined value is used to decided a conditional
* jump or a load/store address. So if we poison all of our inputs we
* can confirm that the operations in question are truly const time
* when compiled by whatever compiler is in use.
*
* Even better, the VALGRIND_MAKE_MEM_* macros work even when the
* program is not run under valgrind (though with a few cycles of
* overhead, which is unfortunate in final binaries as these
* annotations tend to be used in fairly important loops).
*
* This approach was first used in ctgrind (https://github.com/agl/ctgrind)
* but calling the valgrind mecheck API directly works just as well and
* doesn't require a custom patched valgrind.
*/
template <typename T>
inline void poison(const T* p, size_t n) {
#if defined(BOTAN_HAS_VALGRIND)
   if(!std::is_constant_evaluated()) {
      VALGRIND_MAKE_MEM_UNDEFINED(p, n * sizeof(T));
   }
#endif

   BOTAN_UNUSED(p, n);
}

template <typename T>
constexpr inline void unpoison(const T* p, size_t n) {
#if defined(BOTAN_HAS_VALGRIND)
   if(!std::is_constant_evaluated()) {
      VALGRIND_MAKE_MEM_DEFINED(p, n * sizeof(T));
   }
#endif

   BOTAN_UNUSED(p, n);
}

template <typename T>
constexpr inline void unpoison(T& p) {
#if defined(BOTAN_HAS_VALGRIND)
   if(!std::is_constant_evaluated()) {
      VALGRIND_MAKE_MEM_DEFINED(&p, sizeof(T));
   }
#endif

   BOTAN_UNUSED(p);
}

/**
* A Mask type used for constant-time operations. A Mask<T> always has value
* either 0 (all bits cleared) or ~0 (all bits set). All operations in a Mask<T>
* are intended to compile to code which does not contain conditional jumps.
* This must be verified with tooling (eg binary disassembly or using valgrind)
* since you never know what a compiler might do.
*/
template <typename T>
class Mask final {
   public:
      static_assert(std::is_unsigned<T>::value && !std::is_same<bool, T>::value,
                    "Only unsigned integer types are supported by CT::Mask");

      Mask(const Mask<T>& other) = default;
      Mask<T>& operator=(const Mask<T>& other) = default;

      /**
      * Derive a Mask from a Mask of a larger type
      */
      template <typename U>
      constexpr Mask(Mask<U> o) : m_mask(static_cast<T>(o.value())) {
         static_assert(sizeof(U) > sizeof(T), "sizes ok");
      }

      /**
      * Return a Mask<T> with all bits set
      */
      static constexpr Mask<T> set() { return Mask<T>(static_cast<T>(~0)); }

      /**
      * Return a Mask<T> with all bits cleared
      */
      static constexpr Mask<T> cleared() { return Mask<T>(0); }

      /**
      * Return a Mask<T> which is set if v is != 0
      */
      static constexpr Mask<T> expand(T v) { return ~Mask<T>::is_zero(v); }

      /**
      * Return a Mask<T> which is set if m is set
      */
      template <typename U>
      static constexpr Mask<T> expand(Mask<U> m) {
         static_assert(sizeof(U) < sizeof(T), "sizes ok");
         return ~Mask<T>::is_zero(m.value());
      }

      /**
      * Return a Mask<T> which is set if v is == 0 or cleared otherwise
      */
      static constexpr Mask<T> is_zero(T x) { return Mask<T>(ct_is_zero<T>(x)); }

      /**
      * Return a Mask<T> which is set if x == y
      */
      static constexpr Mask<T> is_equal(T x, T y) { return Mask<T>::is_zero(static_cast<T>(x ^ y)); }

      /**
      * Return a Mask<T> which is set if x < y
      */
      static constexpr Mask<T> is_lt(T x, T y) { return Mask<T>(expand_top_bit<T>(x ^ ((x ^ y) | ((x - y) ^ x)))); }

      /**
      * Return a Mask<T> which is set if x > y
      */
      static constexpr Mask<T> is_gt(T x, T y) { return Mask<T>::is_lt(y, x); }

      /**
      * Return a Mask<T> which is set if x <= y
      */
      static constexpr Mask<T> is_lte(T x, T y) { return ~Mask<T>::is_gt(x, y); }

      /**
      * Return a Mask<T> which is set if x >= y
      */
      static constexpr Mask<T> is_gte(T x, T y) { return ~Mask<T>::is_lt(x, y); }

      static constexpr Mask<T> is_within_range(T v, T l, T u) {
         //return Mask<T>::is_gte(v, l) & Mask<T>::is_lte(v, u);

         const T v_lt_l = v ^ ((v ^ l) | ((v - l) ^ v));
         const T v_gt_u = u ^ ((u ^ v) | ((u - v) ^ u));
         const T either = v_lt_l | v_gt_u;
         return ~Mask<T>(expand_top_bit(either));
      }

      static constexpr Mask<T> is_any_of(T v, std::initializer_list<T> accepted) {
         T accept = 0;

         for(auto a : accepted) {
            const T diff = a ^ v;
            const T eq_zero = ~diff & (diff - 1);
            accept |= eq_zero;
         }

         return Mask<T>(expand_top_bit(accept));
      }

      /**
      * AND-combine two masks
      */
      Mask<T>& operator&=(Mask<T> o) {
         m_mask &= o.value();
         return (*this);
      }

      /**
      * XOR-combine two masks
      */
      Mask<T>& operator^=(Mask<T> o) {
         m_mask ^= o.value();
         return (*this);
      }

      /**
      * OR-combine two masks
      */
      Mask<T>& operator|=(Mask<T> o) {
         m_mask |= o.value();
         return (*this);
      }

      /**
      * AND-combine two masks
      */
      friend Mask<T> operator&(Mask<T> x, Mask<T> y) { return Mask<T>(x.value() & y.value()); }

      /**
      * XOR-combine two masks
      */
      friend Mask<T> operator^(Mask<T> x, Mask<T> y) { return Mask<T>(x.value() ^ y.value()); }

      /**
      * OR-combine two masks
      */
      friend Mask<T> operator|(Mask<T> x, Mask<T> y) { return Mask<T>(x.value() | y.value()); }

      /**
      * Negate this mask
      */
      constexpr Mask<T> operator~() const { return Mask<T>(~value()); }

      /**
      * Return x if the mask is set, or otherwise zero
      */
      constexpr T if_set_return(T x) const { return m_mask & x; }

      /**
      * Return x if the mask is cleared, or otherwise zero
      */
      constexpr T if_not_set_return(T x) const { return ~m_mask & x; }

      /**
      * If this mask is set, return x, otherwise return y
      */
      constexpr T select(T x, T y) const { return choose(value(), x, y); }

      constexpr T select_and_unpoison(T x, T y) const {
         T r = this->select(x, y);
         CT::unpoison(r);
         return r;
      }

      /**
      * If this mask is set, return x, otherwise return y
      */
      Mask<T> select_mask(Mask<T> x, Mask<T> y) const { return Mask<T>(select(x.value(), y.value())); }

      /**
      * Conditionally set output to x or y, depending on if mask is set or
      * cleared (resp)
      */
      constexpr void select_n(T output[], const T x[], const T y[], size_t len) const {
         for(size_t i = 0; i != len; ++i) {
            output[i] = this->select(x[i], y[i]);
         }
      }

      /**
      * If this mask is set, zero out buf, otherwise do nothing
      */
      constexpr void if_set_zero_out(T buf[], size_t elems) {
         for(size_t i = 0; i != elems; ++i) {
            buf[i] = this->if_not_set_return(buf[i]);
         }
      }

      /**
      * Return the value of the mask, unpoisoned
      */
      constexpr T unpoisoned_value() const {
         T r = value();
         CT::unpoison(r);
         return r;
      }

      /**
      * Return true iff this mask is set
      */
      constexpr bool as_bool() const { return unpoisoned_value() != 0; }

      /**
      * Return the underlying value of the mask
      */
      constexpr T value() const { return m_mask; }

   private:
      constexpr Mask(T m) : m_mask(m) {}

      T m_mask;
};

template <typename T>
constexpr inline Mask<T> conditional_copy_mem(Mask<T> mask, T* to, const T* from0, const T* from1, size_t elems) {
   mask.select_n(to, from0, from1, elems);
   return mask;
}

template <typename T>
constexpr inline Mask<T> conditional_copy_mem(T cnd, T* to, const T* from0, const T* from1, size_t elems) {
   const auto mask = CT::Mask<T>::expand(cnd);
   return CT::conditional_copy_mem(mask, to, from0, from1, elems);
}

template <typename T>
constexpr inline Mask<T> conditional_assign_mem(T cnd, T* sink, const T* src, size_t elems) {
   const auto mask = CT::Mask<T>::expand(cnd);
   mask.select_n(sink, src, sink, elems);
   return mask;
}

template <typename T>
constexpr inline void conditional_swap(bool cnd, T& x, T& y) {
   const auto swap = CT::Mask<T>::expand(cnd);

   T t0 = swap.select(y, x);
   T t1 = swap.select(x, y);
   x = t0;
   y = t1;
}

template <typename T>
constexpr inline void conditional_swap_ptr(bool cnd, T& x, T& y) {
   uintptr_t xp = reinterpret_cast<uintptr_t>(x);
   uintptr_t yp = reinterpret_cast<uintptr_t>(y);

   conditional_swap<uintptr_t>(cnd, xp, yp);

   x = reinterpret_cast<T>(xp);
   y = reinterpret_cast<T>(yp);
}

template <typename T>
constexpr inline CT::Mask<T> all_zeros(const T elem[], size_t len) {
   T sum = 0;
   for(size_t i = 0; i != len; ++i) {
      sum |= elem[i];
   }
   return CT::Mask<T>::is_zero(sum);
}

/**
* Compare two arrays of equal size and return a Mask indicating if
* they are equal or not. The mask is set if they are identical.
*/
template <typename T>
constexpr inline CT::Mask<T> is_equal(const T x[], const T y[], size_t len) {
   if(std::is_constant_evaluated()) {
      T difference = 0;

      for(size_t i = 0; i != len; ++i) {
         difference = difference | (x[i] ^ y[i]);
      }

      return CT::Mask<T>::is_zero(difference);
   } else {
      volatile T difference = 0;

      for(size_t i = 0; i != len; ++i) {
         difference = difference | (x[i] ^ y[i]);
      }

      return CT::Mask<T>::is_zero(difference);
   }
}

/**
* Compare two arrays of equal size and return a Mask indicating if
* they are equal or not. The mask is set if they differ.
*/
template <typename T>
constexpr inline CT::Mask<T> is_not_equal(const T x[], const T y[], size_t len) {
   return ~CT::is_equal(x, y, len);
}

/**
* If bad_input is unset, return input[offset:input_length] copied to new
* buffer. If bad_input is set, return an empty vector. In all cases, the capacity
* of the vector is equal to input_length
*
* This function attempts to avoid leaking the following:
*  - if bad_input was set or not
*  - the value of offset
*  - the values in input[]
*
* This function leaks the value of input_length
*/
BOTAN_TEST_API
secure_vector<uint8_t> copy_output(CT::Mask<uint8_t> bad_input,
                                   const uint8_t input[],
                                   size_t input_length,
                                   size_t offset);

secure_vector<uint8_t> strip_leading_zeros(const uint8_t in[], size_t length);

inline secure_vector<uint8_t> strip_leading_zeros(const secure_vector<uint8_t>& in) {
   return strip_leading_zeros(in.data(), in.size());
}

}  // namespace Botan::CT

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_CPU_HAS_NATIVE_64BIT)
   #include <intrin.h>
#endif

namespace Botan {

/**
* Perform a 64x64->128 bit multiplication
*/
constexpr inline void mul64x64_128(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi) {
   if(!std::is_constant_evaluated()) {
#if defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_ARCH_IS_X86_64)
      *lo = _umul128(a, b, hi);
      return;

#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_ARCH_IS_ARM64)
      *lo = a * b;
      *hi = __umulh(a, b);
      return;
#endif
   }

#if defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
   const uint128_t r = static_cast<uint128_t>(a) * b;
   *hi = (r >> 64) & 0xFFFFFFFFFFFFFFFF;
   *lo = (r)&0xFFFFFFFFFFFFFFFF;
#else

   /*
   * Do a 64x64->128 multiply using four 32x32->64 multiplies plus
   * some adds and shifts.
   */
   const size_t HWORD_BITS = 32;
   const uint32_t HWORD_MASK = 0xFFFFFFFF;

   const uint32_t a_hi = (a >> HWORD_BITS);
   const uint32_t a_lo = (a & HWORD_MASK);
   const uint32_t b_hi = (b >> HWORD_BITS);
   const uint32_t b_lo = (b & HWORD_MASK);

   const uint64_t x0 = static_cast<uint64_t>(a_hi) * b_hi;
   const uint64_t x1 = static_cast<uint64_t>(a_lo) * b_hi;
   const uint64_t x2 = static_cast<uint64_t>(a_hi) * b_lo;
   const uint64_t x3 = static_cast<uint64_t>(a_lo) * b_lo;

   // this cannot overflow as (2^32-1)^2 + 2^32-1 + 2^32-1 = 2^64-1
   const uint64_t middle = x2 + (x3 >> HWORD_BITS) + (x1 & HWORD_MASK);

   // likewise these cannot overflow
   *hi = x0 + (middle >> HWORD_BITS) + (x1 >> HWORD_BITS);
   *lo = (middle << HWORD_BITS) + (x3 & HWORD_MASK);
#endif
}

}  // namespace Botan

namespace Botan {

class donna128 final {
   public:
      constexpr donna128(uint64_t ll = 0, uint64_t hh = 0) {
         l = ll;
         h = hh;
      }

      donna128(const donna128&) = default;
      donna128& operator=(const donna128&) = default;

      template <typename T>
      constexpr friend donna128 operator>>(const donna128& x, T shift) {
         donna128 z = x;

         if(shift > 64) {
            z.l = z.h >> (shift - 64);
            z.h = 0;
         } else if(shift == 64) {
            z.l = z.h;
            z.h = 0;
         } else if(shift > 0) {
            const uint64_t carry = z.h << static_cast<size_t>(64 - shift);
            z.h >>= shift;
            z.l >>= shift;
            z.l |= carry;
         }

         return z;
      }

      template <typename T>
      constexpr friend donna128 operator<<(const donna128& x, T shift) {
         donna128 z = x;
         if(shift > 64) {
            z.h = z.l << (shift - 64);
            z.l = 0;
         } else if(shift == 64) {
            z.h = z.l;
            z.l = 0;
         } else if(shift > 0) {
            const uint64_t carry = z.l >> static_cast<size_t>(64 - shift);
            z.l = (z.l << shift);
            z.h = (z.h << shift) | carry;
         }

         return z;
      }

      constexpr friend uint64_t operator&(const donna128& x, uint64_t mask) { return x.l & mask; }

      constexpr uint64_t operator&=(uint64_t mask) {
         h = 0;
         l &= mask;
         return l;
      }

      constexpr donna128& operator+=(const donna128& x) {
         l += x.l;
         h += x.h;

         const uint64_t carry = (l < x.l);
         h += carry;
         return *this;
      }

      constexpr donna128& operator+=(uint64_t x) {
         l += x;
         const uint64_t carry = (l < x);
         h += carry;
         return *this;
      }

      constexpr uint64_t lo() const { return l; }

      constexpr uint64_t hi() const { return h; }

      constexpr operator uint64_t() const { return l; }

   private:
      uint64_t h = 0, l = 0;
};

template <std::unsigned_integral T>
constexpr inline donna128 operator*(const donna128& x, T y) {
   BOTAN_ARG_CHECK(x.hi() == 0, "High 64 bits of donna128 set to zero during multiply");

   uint64_t lo = 0, hi = 0;
   mul64x64_128(x.lo(), static_cast<uint64_t>(y), &lo, &hi);
   return donna128(lo, hi);
}

template <std::unsigned_integral T>
constexpr inline donna128 operator*(T y, const donna128& x) {
   return x * y;
}

constexpr inline donna128 operator+(const donna128& x, const donna128& y) {
   donna128 z = x;
   z += y;
   return z;
}

constexpr inline donna128 operator+(const donna128& x, uint64_t y) {
   donna128 z = x;
   z += y;
   return z;
}

constexpr inline donna128 operator|(const donna128& x, const donna128& y) {
   return donna128(x.lo() | y.lo(), x.hi() | y.hi());
}

constexpr inline donna128 operator|(const donna128& x, uint64_t y) {
   return donna128(x.lo() | y, x.hi());
}

constexpr inline uint64_t carry_shift(const donna128& a, size_t shift) {
   return (a >> shift).lo();
}

constexpr inline uint64_t combine_lower(const donna128& a, size_t s1, const donna128& b, size_t s2) {
   donna128 z = (a >> s1) | (b << s2);
   return z.lo();
}

#if defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
inline uint64_t carry_shift(const uint128_t a, size_t shift) {
   return static_cast<uint64_t>(a >> shift);
}

inline uint64_t combine_lower(const uint128_t a, size_t s1, const uint128_t b, size_t s2) {
   return static_cast<uint64_t>((a >> s1) | (b << s2));
}
#endif

}  // namespace Botan

namespace Botan {

/**
* Represents a DLL or shared object
*/
class BOTAN_TEST_API Dynamically_Loaded_Library final {
   public:
      /**
      * Load a DLL (or fail with an exception)
      * @param lib_name name or path to a library
      *
      * If you don't use a full path, the search order will be defined
      * by whatever the system linker does by default. Always using fully
      * qualified pathnames can help prevent code injection attacks (eg
      * via manipulation of LD_LIBRARY_PATH on Linux)
      */
      Dynamically_Loaded_Library(std::string_view lib_name);

      /**
      * Unload the DLL
      * @warning Any pointers returned by resolve()/resolve_symbol()
      * should not be used after this destructor runs.
      */
      ~Dynamically_Loaded_Library();

      /**
      * Load a symbol (or fail with an exception)
      * @param symbol names the symbol to load
      * @return address of the loaded symbol
      */
      void* resolve_symbol(const std::string& symbol);

      /**
      * Convenience function for casting symbol to the right type
      * @param symbol names the symbol to load
      * @return address of the loaded symbol
      */
      template <typename T>
      T resolve(const std::string& symbol) {
         return reinterpret_cast<T>(resolve_symbol(symbol));
      }

   private:
      Dynamically_Loaded_Library(const Dynamically_Loaded_Library&);
      Dynamically_Loaded_Library& operator=(const Dynamically_Loaded_Library&);

      std::string m_lib_name;
      void* m_lib;
};

}  // namespace Botan

namespace Botan {

/**
* No_Filesystem_Access Exception
*/
class No_Filesystem_Access final : public Exception {
   public:
      No_Filesystem_Access() : Exception("No filesystem access enabled.") {}
};

BOTAN_TEST_API bool has_filesystem_impl();

BOTAN_TEST_API std::vector<std::string> get_files_recursive(std::string_view dir);

}  // namespace Botan

namespace Botan {

namespace fmt_detail {

inline void do_fmt(std::ostringstream& oss, std::string_view format) {
   oss << format;
}

template <typename T, typename... Ts>
void do_fmt(std::ostringstream& oss, std::string_view format, const T& val, const Ts&... rest) {
   size_t i = 0;

   while(i < format.size()) {
      if(format[i] == '{' && (format.size() > (i + 1)) && format.at(i + 1) == '}') {
         oss << val;
         return do_fmt(oss, format.substr(i + 2), rest...);
      } else {
         oss << format[i];
      }

      i += 1;
   }
}

}  // namespace fmt_detail

/**
* Simple formatter utility.
*
* Should be replaced with std::format once that's available on all our
* supported compilers.
*
* '{}' markers in the format string are replaced by the arguments.
* Unlike std::format, there is no support for escaping or for any kind
* of conversion flags.
*/
template <typename... T>
std::string fmt(std::string_view format, const T&... args) {
   std::ostringstream oss;
   oss.imbue(std::locale::classic());
   fmt_detail::do_fmt(oss, format, args...);
   return oss.str();
}

}  // namespace Botan

/**
 * @file loadstor.h
 *
 * @brief This header contains various helper functions to load and store
 *        unsigned integers in big- or little-endian byte order.
 *
 * Storing integer values in various ways (same for BE and LE):
 * @code {.cpp}
 *
 *   std::array<uint8_t, 8> bytes = store_le(some_uint64);
 *   std::array<uint8_t, 12> bytes = store_le(some_uint32_1, some_uint32_2, some_uint32_3, ...);
 *   auto bytes = store_le<std::vector<uint8_t>>(some_uint64);
 *   auto bytes = store_le<MyContainerStrongType>(some_uint64);
 *   auto bytes = store_le<std::vector<uint8_t>>(vector_of_ints);
 *   auto bytes = store_le<secure_vector<uint8_t>>(some_uint32_1, some_uint32_2, some_uint32_3, ...);
 *   store_le(bytes, some_uint64);
 *   store_le(concatenated_bytes, some_uint64_1, some_uint64_2, some_uint64_3, ...);
 *   store_le(concatenated_bytes, vector_of_ints);
 *   copy_out_le(short_concated_bytes, vector_of_ints); // stores as many bytes as required in the output buffer
 *
 * @endcode
 *
 * Loading integer values in various ways (same for BE and LE):
 * @code {.cpp}
 *
 *   uint64_t some_uint64 = load_le(bytes_8);
 *   auto some_int32s = load_le<std::vector<uint32_t>>(concatenated_bytes);
 *   auto some_int32s = load_le<std::vector<MyIntStrongType>>(concatenated_bytes);
 *   auto some_int32s = load_le(some_strong_typed_bytes);
 *   auto strong_int  = load_le<MyStrongTypedInteger>(concatenated_bytes);
 *   load_le(concatenated_bytes, out_some_uint64);
 *   load_le(concatenated_bytes, out_some_uint64_1, out_some_uint64_2, out_some_uint64_3, ...);
 *   load_le(out_vector_of_ints, concatenated_bytes);
 *
 * @endcode
 */

namespace Botan {

/**
* Byte extraction
* @param byte_num which byte to extract, 0 == highest byte
* @param input the value to extract from
* @return byte byte_num of input
*/
template <typename T>
inline constexpr uint8_t get_byte_var(size_t byte_num, T input) {
   return static_cast<uint8_t>(input >> (((~byte_num) & (sizeof(T) - 1)) << 3));
}

/**
* Byte extraction
* @param input the value to extract from
* @return byte byte number B of input
*/
template <size_t B, typename T>
inline constexpr uint8_t get_byte(T input)
   requires(B < sizeof(T))
{
   const size_t shift = ((~B) & (sizeof(T) - 1)) << 3;
   return static_cast<uint8_t>((input >> shift) & 0xFF);
}

/**
* Make a uint16_t from two bytes
* @param i0 the first byte
* @param i1 the second byte
* @return i0 || i1
*/
inline constexpr uint16_t make_uint16(uint8_t i0, uint8_t i1) {
   return static_cast<uint16_t>((static_cast<uint16_t>(i0) << 8) | i1);
}

/**
* Make a uint32_t from four bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @return i0 || i1 || i2 || i3
*/
inline constexpr uint32_t make_uint32(uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3) {
   return ((static_cast<uint32_t>(i0) << 24) | (static_cast<uint32_t>(i1) << 16) | (static_cast<uint32_t>(i2) << 8) |
           (static_cast<uint32_t>(i3)));
}

/**
* Make a uint64_t from eight bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @param i4 the fifth byte
* @param i5 the sixth byte
* @param i6 the seventh byte
* @param i7 the eighth byte
* @return i0 || i1 || i2 || i3 || i4 || i5 || i6 || i7
*/
inline constexpr uint64_t make_uint64(
   uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3, uint8_t i4, uint8_t i5, uint8_t i6, uint8_t i7) {
   return ((static_cast<uint64_t>(i0) << 56) | (static_cast<uint64_t>(i1) << 48) | (static_cast<uint64_t>(i2) << 40) |
           (static_cast<uint64_t>(i3) << 32) | (static_cast<uint64_t>(i4) << 24) | (static_cast<uint64_t>(i5) << 16) |
           (static_cast<uint64_t>(i6) << 8) | (static_cast<uint64_t>(i7)));
}

namespace detail {

enum class Endianness : bool {
   Big,
   Little,
};

struct AutoDetect {
      constexpr AutoDetect() = delete;
};

/**
 * @warning This function may return false if the native endianness is unknown
 * @returns true iff the native endianness matches the given endianness
 */
constexpr bool is_native(Endianness endianness) {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   return endianness == Endianness::Big;
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   return endianness == Endianness::Little;
#else
   return false;
#endif
}

/**
 * @warning This function may return false if the native endianness is unknown
 * @returns true iff the native endianness does not match the given endianness
 */
constexpr bool is_opposite(Endianness endianness) {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   return endianness == Endianness::Little;
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   return endianness == Endianness::Big;
#else
   return false;
#endif
}

template <Endianness endianness>
constexpr bool native_endianness_is_unknown() {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN) || defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   return false;
#else
   return true;
#endif
}

/**
 * Models a type that can be loaded/stored from/to a byte range.
 */
template <typename T>
concept unsigned_integralish = std::unsigned_integral<T> || concepts::unsigned_integral_strong_type<T> ||
                               (std::is_enum_v<T> && std::unsigned_integral<std::underlying_type_t<T>>);

/**
 * Manually load a word from a range in either big or little endian byte order.
 * This will be used only if the endianness of the target platform is unknown at
 * compile time.
 */
template <Endianness endianness, std::unsigned_integral OutT, ranges::contiguous_range<uint8_t> InR>
inline constexpr OutT fallback_load_any(InR&& in_range) {
   std::span in{in_range};
   // clang-format off
   if constexpr(endianness == Endianness::Big) {
      return [&]<size_t... i>(std::index_sequence<i...>) {
         return static_cast<OutT>(((static_cast<OutT>(in[i]) << ((sizeof(OutT) - i - 1) * 8)) | ...));
      } (std::make_index_sequence<sizeof(OutT)>());
   } else {
      static_assert(endianness == Endianness::Little);
      return [&]<size_t... i>(std::index_sequence<i...>) {
         return static_cast<OutT>(((static_cast<OutT>(in[i]) << (i * 8)) | ...));
      } (std::make_index_sequence<sizeof(OutT)>());
   }
   // clang-format on
}

/**
 * Manually store a word into a range in either big or little endian byte order.
 * This will be used only if the endianness of the target platform is unknown at
 * compile time.
 */
template <Endianness endianness, std::unsigned_integral InT, ranges::contiguous_output_range<uint8_t> OutR>
inline constexpr void fallback_store_any(InT in, OutR&& out_range) {
   std::span out{out_range};
   // clang-format off
   if constexpr(endianness == Endianness::Big) {
      [&]<size_t... i>(std::index_sequence<i...>) {
         ((out[i] = get_byte<i>(in)), ...);
      } (std::make_index_sequence<sizeof(InT)>());
   } else {
      static_assert(endianness == Endianness::Little);
      [&]<size_t... i>(std::index_sequence<i...>) {
         ((out[i] = get_byte<sizeof(InT) - i - 1>(in)), ...);
      } (std::make_index_sequence<sizeof(InT)>());
   }
   // clang-format on
}

/**
 * Load a word from a range in either big or little endian byte order
 *
 * This is the base implementation, all other overloads are just convenience
 * wrappers. It is assumed that the range has the correct size for the word.
 *
 * Template arguments of all overloads of load_any() share the same semantics:
 *
 *   1.  Endianness      Either `Endianness::Big` or `Endianness::Little`, that
 *                       will eventually select the byte order translation mode
 *                       implemented in this base function.
 *
 *   2.  Output type     Either `AutoDetect`, an unsigned integer or a container
 *                       holding an unsigned integer type. `AutoDetect` means
 *                       that the caller did not explicitly specify the type and
 *                       expects the type to be inferred from the input.
 *
 *   3+. Argument types  Typically, those are input and output ranges of bytes
 *                       or unsigned integers. Or one or more unsigned integers
 *                       acting as output parameters.
 *
 * @param in_range a fixed-length byte range
 * @return T loaded from @p in_range, as a big-endian value
 */
template <Endianness endianness, std::unsigned_integral OutT, ranges::contiguous_range<uint8_t> InR>
inline constexpr OutT load_any(InR&& in_range) {
   ranges::assert_exact_byte_length<sizeof(OutT)>(in_range);
   std::span in{in_range};

   // At compile time we cannot use `typecast_copy` as it uses `std::memcpy`
   // internally to copy ranges on a byte-by-byte basis, which is not allowed
   // in a `constexpr` context.
   if(std::is_constant_evaluated()) /* TODO: C++23: if consteval {} */ {
      return fallback_load_any<endianness, OutT>(std::forward<InR>(in_range));
   } else {
      if constexpr(sizeof(OutT) == 1) {
         return static_cast<OutT>(in[0]);
      } else if constexpr(is_native(endianness)) {
         return typecast_copy<OutT>(in);
      } else if constexpr(is_opposite(endianness)) {
         return reverse_bytes(typecast_copy<OutT>(in));
      } else {
         static_assert(native_endianness_is_unknown<endianness>());
         return fallback_load_any<endianness, OutT>(std::forward<InR>(in_range));
      }
   }
}

/**
 * Overload for loading into a strong type holding an unsigned integer
 */
template <Endianness endianness, concepts::unsigned_integral_strong_type OutT, ranges::contiguous_range<uint8_t> InR>
inline constexpr OutT load_any(InR&& in_range) {
   using underlying_type = typename OutT::wrapped_type;
   return OutT{load_any<endianness, underlying_type>(std::forward<InR>(in_range))};
}

/**
 * Overload for loading into an enum type that uses an unsigned integer as its
 * underlying type.
 */
template <Endianness endianness, typename OutT, ranges::contiguous_range<uint8_t> InR>
   requires(std::is_enum_v<OutT> && std::unsigned_integral<std::underlying_type_t<OutT>>)
inline constexpr OutT load_any(InR&& in_range) {
   using underlying_type = std::underlying_type_t<OutT>;
   return static_cast<OutT>(load_any<endianness, underlying_type>(std::forward<InR>(in_range)));
}

/**
 * Load many unsigned integers
 * @param in   a fixed-length span to some bytes
 * @param outs a arbitrary-length parameter list of unsigned integers to be loaded
 */
template <Endianness endianness, typename OutT, ranges::contiguous_range<uint8_t> InR, unsigned_integralish... Ts>
   requires(sizeof...(Ts) > 0) && ((std::same_as<AutoDetect, OutT> && all_same_v<Ts...>) ||
                                   (unsigned_integralish<OutT> && all_same_v<OutT, Ts...>))
inline constexpr void load_any(InR&& in, Ts&... outs) {
   ranges::assert_exact_byte_length<(sizeof(Ts) + ...)>(in);
   auto load_one = [off = 0]<typename T>(auto i, T& o) mutable {
      o = load_any<endianness, T>(i.subspan(off).template first<sizeof(T)>());
      off += sizeof(T);
   };

   (load_one(std::span{in}, outs), ...);
}

/**
 * Load a variable number of words from @p in into @p out.
 * The byte length of the @p out and @p in ranges must match.
 *
 * @param out the output range of words
 * @param in the input range of bytes
 */
template <Endianness endianness,
          typename OutT,
          ranges::contiguous_output_range OutR,
          ranges::contiguous_range<uint8_t> InR>
   requires(unsigned_integralish<std::ranges::range_value_t<OutR>> &&
            (std::same_as<AutoDetect, OutT> || std::same_as<OutT, std::ranges::range_value_t<OutR>>))
inline constexpr void load_any(OutR&& out, InR&& in) {
   ranges::assert_equal_byte_lengths(out, in);

   auto load_elementwise = [&] {
      using element_type = std::ranges::range_value_t<OutR>;
      constexpr size_t bytes_per_element = sizeof(element_type);
      std::span<const uint8_t> in_s(in);
      for(auto& out_elem : out) {
         out_elem = load_any<endianness, element_type>(in_s.template first<bytes_per_element>());
         in_s = in_s.subspan(bytes_per_element);
      }
   };

   // At compile time we cannot use `typecast_copy` as it uses `std::memcpy`
   // internally to copy ranges on a byte-by-byte basis, which is not allowed
   // in a `constexpr` context.
   if(std::is_constant_evaluated()) /* TODO: C++23: if consteval {} */ {
      load_elementwise();
   } else {
      if constexpr(is_native(endianness)) {
         typecast_copy(out, in);
      } else {
         load_elementwise();
      }
   }
}

//
// Type inference overloads
//

/**
 * Load one or more unsigned integers, auto-detect the output type if
 * possible. Otherwise, use the specified integer or integer container type.
 *
 * @param in_range a statically-sized range with some bytes
 * @return T loaded from in
 */
template <Endianness endianness, typename OutT, ranges::contiguous_range<uint8_t> InR>
   requires(std::same_as<AutoDetect, OutT> ||
            ((ranges::statically_spanable_range<OutT> ||
              concepts::resizable_container<OutT>)&&unsigned_integralish<typename OutT::value_type>))
inline constexpr auto load_any(InR&& in_range) {
   auto out = []([[maybe_unused]] const auto& in) {
      if constexpr(std::same_as<AutoDetect, OutT>) {
         if constexpr(ranges::statically_spanable_range<InR>) {
            constexpr size_t extent = decltype(std::span{in})::extent;

            // clang-format off
            using type =
               std::conditional_t<extent == 1, uint8_t,
               std::conditional_t<extent == 2, uint16_t,
               std::conditional_t<extent == 4, uint32_t,
               std::conditional_t<extent == 8, uint64_t, void>>>>;
            // clang-format on

            static_assert(
               !std::is_void_v<type>,
               "Cannot determine the output type based on a statically sized bytearray with length other than those: 1, 2, 4, 8");

            return type{};
         } else {
            static_assert(
               !std::same_as<AutoDetect, OutT>,
               "cannot infer return type from a dynamic range at compile time, please specify it explicitly");
         }
      } else if constexpr(concepts::resizable_container<OutT>) {
         const size_t in_bytes = std::span{in}.size_bytes();
         constexpr size_t out_elem_bytes = sizeof(typename OutT::value_type);
         BOTAN_ARG_CHECK(in_bytes % out_elem_bytes == 0,
                         "Input range is not word-aligned with the requested output range");
         return OutT(in_bytes / out_elem_bytes);
      } else {
         return OutT{};
      }
   }(in_range);

   using out_type = decltype(out);
   if constexpr(unsigned_integralish<out_type>) {
      out = load_any<endianness, out_type>(std::forward<InR>(in_range));
   } else {
      static_assert(ranges::contiguous_range<out_type>);
      using out_range_type = std::ranges::range_value_t<out_type>;
      load_any<endianness, out_range_type>(out, std::forward<InR>(in_range));
   }
   return out;
}

//
// Legacy load functions that work on raw pointers and arrays
//

/**
 * Load a word from @p in at some offset @p off
 * @param in a pointer to some bytes
 * @param off an offset into the array
 * @return off'th T of in, as a big-endian value
 */
template <Endianness endianness, unsigned_integralish OutT>
inline constexpr OutT load_any(const uint8_t in[], size_t off) {
   // asserts that *in points to enough bytes to read at offset off
   constexpr size_t out_size = sizeof(OutT);
   return load_any<endianness, OutT>(std::span<const uint8_t, out_size>(in + off * out_size, out_size));
}

/**
 * Load many words from @p in
 * @param in   a pointer to some bytes
 * @param outs a arbitrary-length parameter list of unsigned integers to be loaded
 */
template <Endianness endianness, typename OutT, unsigned_integralish... Ts>
   requires(sizeof...(Ts) > 0 && all_same_v<Ts...> &&
            ((std::same_as<AutoDetect, OutT> && all_same_v<Ts...>) ||
             (unsigned_integralish<OutT> && all_same_v<OutT, Ts...>)))
inline constexpr void load_any(const uint8_t in[], Ts&... outs) {
   constexpr auto bytes = (sizeof(outs) + ...);
   // asserts that *in points to the correct amount of memory
   load_any<endianness, OutT>(std::span<const uint8_t, bytes>(in, bytes), outs...);
}

/**
 * Load a variable number of words from @p in into @p out.
 * @param out the output array of words
 * @param in the input array of bytes
 * @param count how many words are in in
 */
template <Endianness endianness, typename OutT, unsigned_integralish T>
   requires(std::same_as<AutoDetect, OutT> || std::same_as<T, OutT>)
inline constexpr void load_any(T out[], const uint8_t in[], size_t count) {
   // asserts that *in and *out point to the correct amount of memory
   load_any<endianness, OutT>(std::span<T>(out, count), std::span<const uint8_t>(in, count * sizeof(T)));
}

}  // namespace detail

/**
 * Load "something" in little endian byte order
 * See the documentation of this file for more details.
 */
template <typename OutT = detail::AutoDetect, typename... ParamTs>
inline constexpr auto load_le(ParamTs&&... params) {
   return detail::load_any<detail::Endianness::Little, OutT>(std::forward<ParamTs>(params)...);
}

/**
 * Load "something" in big endian byte order
 * See the documentation of this file for more details.
 */
template <typename OutT = detail::AutoDetect, typename... ParamTs>
inline constexpr auto load_be(ParamTs&&... params) {
   return detail::load_any<detail::Endianness::Big, OutT>(std::forward<ParamTs>(params)...);
}

namespace detail {

/**
 * Store a word in either big or little endian byte order into a range
 *
 * This is the base implementation, all other overloads are just convenience
 * wrappers. It is assumed that the range has the correct size for the word.
 *
 * Template arguments of all overloads of store_any() share the same semantics
 * as those of load_any(). See the documentation of this function for more
 * details.
 *
 * @param in an unsigned integral to be stored
 * @param out_range a byte range to store the word into
 */
template <Endianness endianness, std::unsigned_integral InT, ranges::contiguous_output_range<uint8_t> OutR>
inline constexpr void store_any(InT in, OutR&& out_range) {
   ranges::assert_exact_byte_length<sizeof(InT)>(out_range);
   std::span out{out_range};

   // At compile time we cannot use `typecast_copy` as it uses `std::memcpy`
   // internally to copy ranges on a byte-by-byte basis, which is not allowed
   // in a `constexpr` context.
   if(std::is_constant_evaluated()) /* TODO: C++23: if consteval {} */ {
      return fallback_store_any<endianness, InT>(in, std::forward<OutR>(out_range));
   } else {
      if constexpr(sizeof(InT) == 1) {
         out[0] = static_cast<uint8_t>(in);
      } else if constexpr(is_native(endianness)) {
         typecast_copy(out, in);
      } else if constexpr(is_opposite(endianness)) {
         typecast_copy(out, reverse_bytes(in));
      } else {
         static_assert(native_endianness_is_unknown<endianness>());
         return fallback_store_any<endianness, InT>(in, std::forward<OutR>(out_range));
      }
   }
}

/**
 * Overload for loading into a strong type holding an unsigned integer
 */
template <Endianness endianness,
          concepts::unsigned_integral_strong_type InT,
          ranges::contiguous_output_range<uint8_t> OutR>
inline constexpr void store_any(InT in, OutR&& out_range) {
   using underlying_type = typename InT::wrapped_type;
   store_any<endianness, underlying_type>(in.get(), std::forward<OutR>(out_range));
}

/**
 * Overload for storing an enum type that uses an unsigned integer as its
 * underlying type.
 */
template <Endianness endianness, typename InT, ranges::contiguous_output_range<uint8_t> OutR>
   requires(std::is_enum_v<InT> && std::unsigned_integral<std::underlying_type_t<InT>>)
inline constexpr void store_any(InT in, OutR&& out_range) {
   using underlying_type = std::underlying_type_t<InT>;
   // TODO: C++23: use std::to_underlying(in) instead
   store_any<endianness, underlying_type>(static_cast<underlying_type>(in), std::forward<OutR>(out_range));
}

/**
 * Store many unsigned integers words into a byte range
 * @param out a sized range of some bytes
 * @param ins a arbitrary-length parameter list of unsigned integers to be stored
 */
template <Endianness endianness,
          typename InT,
          ranges::contiguous_output_range<uint8_t> OutR,
          unsigned_integralish... Ts>
   requires(sizeof...(Ts) > 0) && ((std::same_as<AutoDetect, InT> && all_same_v<Ts...>) ||
                                   (unsigned_integralish<InT> && all_same_v<InT, Ts...>))
inline constexpr void store_any(OutR&& out, Ts... ins) {
   ranges::assert_exact_byte_length<(sizeof(Ts) + ...)>(out);
   auto store_one = [off = 0]<typename T>(auto o, T i) mutable {
      store_any<endianness, T>(i, o.subspan(off).template first<sizeof(T)>());
      off += sizeof(T);
   };

   (store_one(std::span{out}, ins), ...);
}

/**
 * Store a variable number of words given in @p in into @p out.
 * The byte lengths of @p in and @p out must be consistent.
 * @param out the output range of bytes
 * @param in the input range of words
 */
template <Endianness endianness,
          typename InT,
          ranges::contiguous_output_range<uint8_t> OutR,
          ranges::spanable_range InR>
   requires(std::same_as<AutoDetect, InT> || std::same_as<InT, std::ranges::range_value_t<InR>>)
inline constexpr void store_any(OutR&& out, InR&& in) {
   ranges::assert_equal_byte_lengths(out, in);

   auto store_elementwise = [&] {
      using element_type = std::ranges::range_value_t<InR>;
      constexpr size_t bytes_per_element = sizeof(element_type);
      std::span<uint8_t> out_s(out);
      for(auto in_elem : in) {
         store_any<endianness, element_type>(out_s.template first<bytes_per_element>(), in_elem);
         out_s = out_s.subspan(bytes_per_element);
      }
   };

   // At compile time we cannot use `typecast_copy` as it uses `std::memcpy`
   // internally to copy ranges on a byte-by-byte basis, which is not allowed
   // in a `constexpr` context.
   if(std::is_constant_evaluated()) /* TODO: C++23: if consteval {} */ {
      store_elementwise();
   } else {
      if constexpr(is_native(endianness)) {
         typecast_copy(out, in);
      } else {
         store_elementwise();
      }
   }
}

//
// Type inference overloads
//

/**
 * Infer InT from a single unsigned integer input parameter.
 *
 * TODO: we might consider dropping this overload (i.e. out-range as second
 *       parameter) and make this a "special case" of the overload below, that
 *       takes a variadic number of input parameters.
 *
 * @param in an unsigned integer to be stored
 * @param out_range a range of bytes to store the word into
 */
template <Endianness endianness, typename InT, unsigned_integralish T, ranges::contiguous_output_range<uint8_t> OutR>
   requires std::same_as<AutoDetect, InT>
inline constexpr void store_any(T in, OutR&& out_range) {
   store_any<endianness, T>(in, std::forward<OutR>(out_range));
}

/**
 * The caller provided some integer values in a collection but did not provide
 * the output container. Let's create one for them, fill it with one of the
 * overloads above and return it. This will default to a std::array if the
 * caller did not specify the desired output container type.
 *
 * @param in_range a range of words that should be stored
 * @return a container of bytes that contains the stored words
 */
template <Endianness endianness, typename OutR, ranges::spanable_range InR>
   requires(std::same_as<AutoDetect, OutR> ||
            (ranges::statically_spanable_range<OutR> && std::default_initializable<OutR>) ||
            concepts::resizable_byte_buffer<OutR>)
inline constexpr auto store_any(InR&& in_range) {
   auto out = []([[maybe_unused]] const auto& in) {
      if constexpr(std::same_as<AutoDetect, OutR>) {
         if constexpr(ranges::statically_spanable_range<InR>) {
            constexpr size_t bytes = decltype(std::span{in})::extent * sizeof(std::ranges::range_value_t<InR>);
            return std::array<uint8_t, bytes>();
         } else {
            static_assert(
               !std::same_as<AutoDetect, OutR>,
               "cannot infer a suitable result container type from the given parameters at compile time, please specify it explicitly");
         }
      } else if constexpr(concepts::resizable_byte_buffer<OutR>) {
         return OutR(std::span{in}.size_bytes());
      } else {
         return OutR{};
      }
   }(in_range);

   store_any<endianness, std::ranges::range_value_t<InR>>(out, std::forward<InR>(in_range));
   return out;
}

/**
 * The caller provided some integer values but did not provide the output
 * container. Let's create one for them, fill it with one of the overloads above
 * and return it. This will default to a std::array if the caller did not
 * specify the desired output container type.
 *
 * @param ins some words that should be stored
 * @return a container of bytes that contains the stored words
 */
template <Endianness endianness, typename OutR, unsigned_integralish... Ts>
   requires all_same_v<Ts...>
inline constexpr auto store_any(Ts... ins) {
   return store_any<endianness, OutR>(std::array{ins...});
}

//
// Legacy store functions that work on raw pointers and arrays
//

/**
 * Store a single unsigned integer into a raw pointer
 * @param in the input unsigned integer
 * @param out the byte array to write to
 */
template <Endianness endianness, typename InT, unsigned_integralish T>
   requires(std::same_as<AutoDetect, InT> || std::same_as<T, InT>)
inline constexpr void store_any(T in, uint8_t out[]) {
   // asserts that *out points to enough bytes to write into
   store_any<endianness, InT>(in, std::span<uint8_t, sizeof(T)>(out, sizeof(T)));
}

/**
 * Store many unsigned integers words into a raw pointer
 * @param ins a arbitrary-length parameter list of unsigned integers to be stored
 * @param out the byte array to write to
 */
template <Endianness endianness, typename InT, unsigned_integralish T0, unsigned_integralish... Ts>
   requires(std::same_as<AutoDetect, InT> || std::same_as<T0, InT>) && all_same_v<T0, Ts...>
inline constexpr void store_any(uint8_t out[], T0 in0, Ts... ins) {
   constexpr auto bytes = sizeof(in0) + (sizeof(ins) + ... + 0);
   // asserts that *out points to the correct amount of memory
   store_any<endianness, T0>(std::span<uint8_t, bytes>(out, bytes), in0, ins...);
}

}  // namespace detail

/**
 * Store "something" in little endian byte order
 * See the documentation of this file for more details.
 */
template <typename ModifierT = detail::AutoDetect, typename... ParamTs>
inline constexpr auto store_le(ParamTs&&... params) {
   return detail::store_any<detail::Endianness::Little, ModifierT>(std::forward<ParamTs>(params)...);
}

/**
 * Store "something" in big endian byte order
 * See the documentation of this file for more details.
 */
template <typename ModifierT = detail::AutoDetect, typename... ParamTs>
inline constexpr auto store_be(ParamTs&&... params) {
   return detail::store_any<detail::Endianness::Big, ModifierT>(std::forward<ParamTs>(params)...);
}

namespace detail {

template <Endianness endianness, unsigned_integralish T>
size_t copy_out_any_word_aligned_portion(std::span<uint8_t>& out, std::span<const T>& in) {
   const size_t full_words = out.size() / sizeof(T);
   const size_t full_word_bytes = full_words * sizeof(T);
   const size_t remaining_bytes = out.size() - full_word_bytes;
   BOTAN_ASSERT_NOMSG(in.size_bytes() >= full_word_bytes + remaining_bytes);

   // copy full words
   store_any<endianness, T>(out.first(full_word_bytes), in.first(full_words));
   out = out.subspan(full_word_bytes);
   in = in.subspan(full_words);

   return remaining_bytes;
}

}  // namespace detail

/**
 * Partially copy a subset of @p in into @p out using big-endian
 * byte order.
 */
template <ranges::spanable_range InR>
void copy_out_be(std::span<uint8_t> out, InR&& in) {
   using T = std::ranges::range_value_t<InR>;
   std::span<const T> in_s{in};
   const auto remaining_bytes = detail::copy_out_any_word_aligned_portion<detail::Endianness::Big>(out, in_s);

   // copy remaining bytes as a partial word
   for(size_t i = 0; i < remaining_bytes; ++i) {
      out[i] = get_byte_var(i, in_s.front());
   }
}

/**
 * Partially copy a subset of @p in into @p out using little-endian
 * byte order.
 */
template <ranges::spanable_range InR>
void copy_out_le(std::span<uint8_t> out, InR&& in) {
   using T = std::ranges::range_value_t<InR>;
   std::span<const T> in_s{in};
   const auto remaining_bytes = detail::copy_out_any_word_aligned_portion<detail::Endianness::Little>(out, in_s);

   // copy remaining bytes as a partial word
   for(size_t i = 0; i < remaining_bytes; ++i) {
      out[i] = get_byte_var(sizeof(T) - 1 - i, in_s.front());
   }
}

}  // namespace Botan

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   #include <thread>
#endif

namespace Botan::OS {

/*
* This header is internal (not installed) and these functions are not
* intended to be called by applications. However they are given public
* visibility (using BOTAN_TEST_API macro) for the tests. This also probably
* allows them to be overridden by the application on ELF systems, but
* this hasn't been tested.
*/

/**
* @return process ID assigned by the operating system.
*
* On Unix and Windows systems, this always returns a result
*
* On systems where there is no processes to speak of (for example on baremetal
* systems or within a unikernel), this function returns zero.
*/
uint32_t BOTAN_TEST_API get_process_id();

/**
* Test if we are currently running with elevated permissions
* eg setuid, setgid, or with POSIX caps set.
*/
bool running_in_privileged_state();

/**
* @return CPU processor clock, if available
*
* On Windows, calls QueryPerformanceCounter.
*
* Under GCC or Clang on supported platforms the hardware cycle counter is queried.
* Currently supported processors are x86, PPC, Alpha, SPARC, IA-64, S/390x, and HP-PA.
* If no CPU cycle counter is available on this system, returns zero.
*/
uint64_t BOTAN_TEST_API get_cpu_cycle_counter();

size_t BOTAN_TEST_API get_cpu_available();

/**
* Return the ELF auxiliary vector cooresponding to the given ID.
* This only makes sense on Unix-like systems and is currently
* only supported on Linux, Android, and FreeBSD.
*
* Returns zero if not supported on the current system or if
* the id provided is not known.
*/
unsigned long get_auxval(unsigned long id);

/*
* @return best resolution timestamp available
*
* The epoch and update rate of this clock is arbitrary and depending
* on the hardware it may not tick at a constant rate.
*
* Uses hardware cycle counter, if available.
* On POSIX platforms clock_gettime is used with a monotonic timer
* As a final fallback std::chrono::high_resolution_clock is used.
*/
uint64_t BOTAN_TEST_API get_high_resolution_clock();

/**
* @return system clock (reflecting wall clock) with best resolution
* available, normalized to nanoseconds resolution.
*/
uint64_t BOTAN_TEST_API get_system_timestamp_ns();

/**
* @return maximum amount of memory (in bytes) Botan could/should
* hyptothetically allocate for the memory poool. Reads environment
* variable "BOTAN_MLOCK_POOL_SIZE", set to "0" to disable pool.
*/
size_t get_memory_locking_limit();

/**
* Return the size of a memory page, if that can be derived on the
* current system. Otherwise returns some default value (eg 4096)
*/
size_t system_page_size();

/**
* Read the value of an environment variable, setting it to value_out if it
* exists.  Returns false and sets value_out to empty string if no such variable
* is set. If the process seems to be running in a privileged state (such as
* setuid) then always returns false and does not examine the environment.
*/
bool read_env_variable(std::string& value_out, std::string_view var_name);

/**
* Read the value of an environment variable and convert it to an
* integer. If not set or conversion fails, returns the default value.
*
* If the process seems to be running in a privileged state (such as setuid)
* then always returns nullptr, similiar to glibc's secure_getenv.
*/
size_t read_env_variable_sz(std::string_view var_name, size_t def_value = 0);

/**
* Request count pages of RAM which are locked into memory using mlock,
* VirtualLock, or some similar OS specific API. Free it with free_locked_pages.
*
* Returns an empty list on failure. This function is allowed to return fewer
* than count pages.
*
* The contents of the allocated pages are undefined.
*
* Each page is preceded by and followed by a page which is marked
* as noaccess, such that accessing it will cause a crash. This turns
* out of bound reads/writes into crash events.
*
* @param count requested number of locked pages
*/
std::vector<void*> allocate_locked_pages(size_t count);

/**
* Free memory allocated by allocate_locked_pages
* @param pages a list of pages returned by allocate_locked_pages
*/
void free_locked_pages(const std::vector<void*>& pages);

/**
* Set the MMU to prohibit access to this page
*/
void page_prohibit_access(void* page);

/**
* Set the MMU to allow R/W access to this page
*/
void page_allow_access(void* page);

/**
* Set a ID to a page's range expressed by size bytes
*/
void page_named(void* page, size_t size);

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
void set_thread_name(std::thread& thread, const std::string& name);
#endif

/**
* Run a probe instruction to test for support for a CPU instruction.
* Runs in system-specific env that catches illegal instructions; this
* function always fails if the OS doesn't provide this.
* Returns value of probe_fn, if it could run.
* If error occurs, returns negative number.
* This allows probe_fn to indicate errors of its own, if it wants.
* For example the instruction might not only be only available on some
* CPUs, but also buggy on some subset of these - the probe function
* can test to make sure the instruction works properly before
* indicating that the instruction is available.
*
* @warning on Unix systems uses signal handling in a way that is not
* thread safe. It should only be called in a single-threaded context
* (ie, at static init time).
*
* If probe_fn throws an exception the result is undefined.
*
* Return codes:
* -1 illegal instruction detected
*/
int BOTAN_TEST_API run_cpu_instruction_probe(const std::function<int()>& probe_fn);

/**
* Represents a terminal state
*/
class BOTAN_UNSTABLE_API Echo_Suppression {
   public:
      /**
      * Reenable echo on this terminal. Can be safely called
      * multiple times. May throw if an error occurs.
      */
      virtual void reenable_echo() = 0;

      /**
      * Implicitly calls reenable_echo, but swallows/ignored all
      * errors which would leave the terminal in an invalid state.
      */
      virtual ~Echo_Suppression() = default;
};

/**
* Suppress echo on the terminal
* Returns null if this operation is not supported on the current system.
*/
std::unique_ptr<Echo_Suppression> BOTAN_UNSTABLE_API suppress_echo_on_terminal();

}  // namespace Botan::OS

namespace Botan {

/**
* Parse a SCAN-style algorithm name
* @param scan_name the name
* @return the name components
*/
std::vector<std::string> parse_algorithm_name(std::string_view scan_name);

/**
* Split a string
* @param str the input string
* @param delim the delimitor
* @return string split by delim
*/
BOTAN_TEST_API std::vector<std::string> split_on(std::string_view str, char delim);

/**
* Join a string
* @param strs strings to join
* @param delim the delimitor
* @return string joined by delim
*/
std::string string_join(const std::vector<std::string>& strs, char delim);

/**
* Convert a decimal string to a number
* @param str the string to convert
* @return number value of the string
*/
BOTAN_TEST_API uint32_t to_u32bit(std::string_view str);

/**
* Convert a decimal string to a number
* @param str the string to convert
* @return number value of the string
*/
uint16_t to_uint16(std::string_view str);

/**
* Convert a string representation of an IPv4 address to a number
* @param ip_str the string representation
* @return integer IPv4 address
*/
uint32_t string_to_ipv4(std::string_view ip_str);

/**
* Convert an IPv4 address to a string
* @param ip_addr the IPv4 address to convert
* @return string representation of the IPv4 address
*/
std::string ipv4_to_string(uint32_t ip_addr);

std::map<std::string, std::string> read_cfg(std::istream& is);

/**
* Accepts key value pairs deliminated by commas:
*
* "" (returns empty map)
* "K=V" (returns map {'K': 'V'})
* "K1=V1,K2=V2"
* "K1=V1,K2=V2,K3=V3"
* "K1=V1,K2=V2,K3=a_value\,with\,commas_and_\=equals"
*
* Values may be empty, keys must be non-empty and unique. Duplicate
* keys cause an exception.
*
* Within both key and value, comma and equals can be escaped with
* backslash. Backslash can also be escaped.
*/
BOTAN_TEST_API
std::map<std::string, std::string> read_kv(std::string_view kv);

std::string tolower_string(std::string_view s);

/**
* Check if the given hostname is a match for the specified wildcard
*/
BOTAN_TEST_API
bool host_wildcard_match(std::string_view wildcard, std::string_view host);

}  // namespace Botan

namespace Botan {

/**
* Prefetch an array
*
* This function returns a uint64_t which is accumulated from values
* read from the array. This may help confuse the compiler sufficiently
* to not elide otherwise "useless" reads. The return value will always
* be zero.
*/
uint64_t prefetch_array_raw(size_t bytes, const void* array) noexcept;

/**
* Prefetch several arrays
*
* This function returns a uint64_t which is accumulated from values
* read from the array. This may help confuse the compiler sufficiently
* to not elide otherwise "useless" reads. The return value will always
* be zero.
*/
template <typename T, size_t... Ns>
T prefetch_arrays(T (&... arr)[Ns]) noexcept
   requires std::is_integral<T>::value
{
   return (static_cast<T>(prefetch_array_raw(sizeof(T) * Ns, arr)) & ...);
}

}  // namespace Botan

namespace Botan {

/**
* Bit rotation left by a compile-time constant amount
* @param input the input word
* @return input rotated left by ROT bits
*/
template <size_t ROT, typename T>
inline constexpr T rotl(T input)
   requires(ROT > 0 && ROT < 8 * sizeof(T))
{
   return static_cast<T>((input << ROT) | (input >> (8 * sizeof(T) - ROT)));
}

/**
* Bit rotation right by a compile-time constant amount
* @param input the input word
* @return input rotated right by ROT bits
*/
template <size_t ROT, typename T>
inline constexpr T rotr(T input)
   requires(ROT > 0 && ROT < 8 * sizeof(T))
{
   return static_cast<T>((input >> ROT) | (input << (8 * sizeof(T) - ROT)));
}

/**
* SHA-2 Sigma style function
*/
template <size_t R1, size_t R2, size_t S, typename T>
inline constexpr T sigma(T x) {
   return rotr<R1>(x) ^ rotr<R2>(x) ^ (x >> S);
}

/**
* SHA-2 Sigma style function
*/
template <size_t R1, size_t R2, size_t R3, typename T>
inline constexpr T rho(T x) {
   return rotr<R1>(x) ^ rotr<R2>(x) ^ rotr<R3>(x);
}

/**
* Bit rotation left, variable rotation amount
* @param input the input word
* @param rot the number of bits to rotate, must be between 0 and sizeof(T)*8-1
* @return input rotated left by rot bits
*/
template <typename T>
inline constexpr T rotl_var(T input, size_t rot) {
   return rot ? static_cast<T>((input << rot) | (input >> (sizeof(T) * 8 - rot))) : input;
}

/**
* Bit rotation right, variable rotation amount
* @param input the input word
* @param rot the number of bits to rotate, must be between 0 and sizeof(T)*8-1
* @return input rotated right by rot bits
*/
template <typename T>
inline constexpr T rotr_var(T input, size_t rot) {
   return rot ? static_cast<T>((input >> rot) | (input << (sizeof(T) * 8 - rot))) : input;
}

#if defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

template <>
inline uint32_t rotl_var(uint32_t input, size_t rot) {
   asm("roll %1,%0" : "+r"(input) : "c"(static_cast<uint8_t>(rot)) : "cc");
   return input;
}

template <>
inline uint32_t rotr_var(uint32_t input, size_t rot) {
   asm("rorl %1,%0" : "+r"(input) : "c"(static_cast<uint8_t>(rot)) : "cc");
   return input;
}

#endif

}  // namespace Botan

namespace Botan {

/**
* Round up
* @param n a non-negative integer
* @param align_to the alignment boundary
* @return n rounded up to a multiple of align_to
*/
inline size_t round_up(size_t n, size_t align_to) {
   BOTAN_ARG_CHECK(align_to != 0, "align_to must not be 0");

   if(n % align_to) {
      n += align_to - (n % align_to);
   }
   return n;
}

/**
* Round down
* @param n an integer
* @param align_to the alignment boundary
* @return n rounded down to a multiple of align_to
*/
template <typename T>
inline constexpr T round_down(T n, T align_to) {
   return (align_to == 0) ? n : (n - (n % align_to));
}

}  // namespace Botan

#if defined(_MSC_VER)
   #include <intsafe.h>
#endif

namespace Botan {

class Integer_Overflow_Detected final : public Exception {
   public:
      Integer_Overflow_Detected(std::string_view file, int line) :
            Exception(fmt("Integer overflow detected at {}:{}", file, line)) {}

      ErrorType error_type() const noexcept override { return ErrorType::InternalError; }
};

inline size_t checked_add(size_t x, size_t y, const char* file, int line) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_add_overflow)
   size_t z;
   if(__builtin_add_overflow(x, y, &z)) [[unlikely]]
#elif defined(_MSC_VER)
   size_t z;
   if(SizeTAdd(x, y, &z) != S_OK) [[unlikely]]
#else
   size_t z = x + y;
   if(z < x) [[unlikely]]
#endif
   {
      throw Integer_Overflow_Detected(file, line);
   }
   return z;
}

inline std::optional<size_t> checked_mul(size_t x, size_t y) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_add_overflow)
   size_t z;
   if(__builtin_mul_overflow(x, y, &z)) [[unlikely]]
#elif defined(_MSC_VER)
   size_t z;
   if(SizeTMult(x, y, &z) != S_OK) [[unlikely]]
#else
   size_t z = x * y;
   if(y && z / y != x) [[unlikely]]
#endif
   {
      return std::nullopt;
   }
   return z;
}

template <typename RT, typename AT>
RT checked_cast_to(AT i) {
   RT c = static_cast<RT>(i);
   if(i != static_cast<AT>(c)) {
      throw Internal_Error("Error during integer conversion");
   }
   return c;
}

#define BOTAN_CHECKED_ADD(x, y) checked_add(x, y, __FILE__, __LINE__)
#define BOTAN_CHECKED_MUL(x, y) checked_mul(x, y)

}  // namespace Botan

namespace Botan {

/**
A class encapsulating a SCAN name (similar to JCE conventions)
http://www.users.zetnet.co.uk/hopwood/crypto/scan/
*/
class SCAN_Name final {
   public:
      /**
      * Create a SCAN_Name
      * @param algo_spec A SCAN-format name
      */
      explicit SCAN_Name(const char* algo_spec);

      /**
      * Create a SCAN_Name
      * @param algo_spec A SCAN-format name
      */
      explicit SCAN_Name(std::string_view algo_spec);

      /**
      * @return original input string
      */
      const std::string& to_string() const { return m_orig_algo_spec; }

      /**
      * @return algorithm name
      */
      const std::string& algo_name() const { return m_alg_name; }

      /**
      * @return number of arguments
      */
      size_t arg_count() const { return m_args.size(); }

      /**
      * @param lower is the lower bound
      * @param upper is the upper bound
      * @return if the number of arguments is between lower and upper
      */
      bool arg_count_between(size_t lower, size_t upper) const {
         return ((arg_count() >= lower) && (arg_count() <= upper));
      }

      /**
      * @param i which argument
      * @return ith argument
      */
      std::string arg(size_t i) const;

      /**
      * @param i which argument
      * @param def_value the default value
      * @return ith argument or the default value
      */
      std::string arg(size_t i, std::string_view def_value) const;

      /**
      * @param i which argument
      * @param def_value the default value
      * @return ith argument as an integer, or the default value
      */
      size_t arg_as_integer(size_t i, size_t def_value) const;

      /**
      * @param i which argument
      * @return ith argument as an integer
      */
      size_t arg_as_integer(size_t i) const;

      /**
      * @return cipher mode (if any)
      */
      std::string cipher_mode() const { return (!m_mode_info.empty()) ? m_mode_info[0] : ""; }

      /**
      * @return cipher mode padding (if any)
      */
      std::string cipher_mode_pad() const { return (m_mode_info.size() >= 2) ? m_mode_info[1] : ""; }

   private:
      std::string m_orig_algo_spec;
      std::string m_alg_name;
      std::vector<std::string> m_args;
      std::vector<std::string> m_mode_info;
};

// This is unrelated but it is convenient to stash it here
template <typename T>
std::vector<std::string> probe_providers_of(std::string_view algo_spec,
                                            const std::vector<std::string>& possible = {"base"}) {
   std::vector<std::string> providers;
   for(auto&& prov : possible) {
      auto o = T::create(algo_spec, prov);
      if(o) {
         providers.push_back(prov);  // available
      }
   }
   return providers;
}

}  // namespace Botan

namespace Botan {

class BOTAN_TEST_API Timer final {
   public:
      Timer(std::string_view name,
            std::string_view provider,
            std::string_view doing,
            uint64_t event_mult,
            size_t buf_size,
            double clock_cycle_ratio,
            uint64_t clock_speed);

      Timer(std::string_view name) : Timer(name, "", "", 1, 0, 0.0, 0) {}

      Timer(std::string_view name, size_t buf_size) : Timer(name, "", "", buf_size, buf_size, 0.0, 0) {}

      Timer(const Timer& other) = default;
      Timer& operator=(const Timer& other) = default;

      void start();

      void stop();

      bool under(std::chrono::milliseconds msec) const { return (milliseconds() < msec.count()); }

      class Timer_Scope final {
         public:
            explicit Timer_Scope(Timer& timer) : m_timer(timer) { m_timer.start(); }

            ~Timer_Scope() {
               try {
                  m_timer.stop();
               } catch(...) {}
            }

         private:
            Timer& m_timer;
      };

      template <typename F>
      auto run(F f) -> decltype(f()) {
         Timer_Scope timer(*this);
         return f();
      }

      template <typename F>
      void run_until_elapsed(std::chrono::milliseconds msec, F f) {
         while(this->under(msec)) {
            run(f);
         }
      }

      uint64_t value() const { return m_time_used; }

      double seconds() const { return milliseconds() / 1000.0; }

      double milliseconds() const { return value() / 1000000.0; }

      double ms_per_event() const { return milliseconds() / events(); }

      uint64_t cycles_consumed() const {
         if(m_clock_speed != 0) {
            return static_cast<uint64_t>((m_clock_speed * value()) / 1000.0);
         }
         return m_cpu_cycles_used;
      }

      uint64_t events() const { return m_event_count * m_event_mult; }

      const std::string& get_name() const { return m_name; }

      const std::string& doing() const { return m_doing; }

      size_t buf_size() const { return m_buf_size; }

      double bytes_per_second() const { return seconds() > 0.0 ? events() / seconds() : 0.0; }

      double events_per_second() const { return seconds() > 0.0 ? events() / seconds() : 0.0; }

      double seconds_per_event() const { return events() > 0 ? seconds() / events() : 0.0; }

      void set_custom_msg(std::string_view s) { m_custom_msg = s; }

      bool operator<(const Timer& other) const;

      std::string to_string() const;

   private:
      std::string result_string_bps() const;
      std::string result_string_ops() const;

      // const data
      std::string m_name, m_doing;
      size_t m_buf_size;
      uint64_t m_event_mult;
      double m_clock_cycle_ratio;
      uint64_t m_clock_speed;

      // set at runtime
      std::string m_custom_msg;
      uint64_t m_time_used = 0, m_timer_start = 0;
      uint64_t m_event_count = 0;

      uint64_t m_max_time = 0, m_min_time = 0;
      uint64_t m_cpu_cycles_start = 0, m_cpu_cycles_used = 0;
};

}  // namespace Botan
/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

void Buffered_Computation::update_be(uint16_t val) {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_be(uint32_t val) {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_be(uint64_t val) {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_le(uint16_t val) {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_le(uint32_t val) {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_le(uint64_t val) {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data({inb, sizeof(inb)});
}

}  // namespace Botan
/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

void SymmetricAlgorithm::throw_key_not_set_error() const {
   throw Key_Not_Set(name());
}

void SymmetricAlgorithm::set_key(std::span<const uint8_t> key) {
   if(!valid_keylength(key.size())) {
      throw Invalid_Key_Length(name(), key.size());
   }
   key_schedule(key);
}

}  // namespace Botan
/*
* OctetString
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <algorithm>

namespace Botan {

/*
* Create an OctetString from RNG output
*/
OctetString::OctetString(RandomNumberGenerator& rng, size_t len) {
   rng.random_vec(m_data, len);
}

/*
* Create an OctetString from a hex string
*/
OctetString::OctetString(std::string_view hex_string) {
   if(!hex_string.empty()) {
      m_data.resize(1 + hex_string.length() / 2);
      m_data.resize(hex_decode(m_data.data(), hex_string));
   }
}

/*
* Create an OctetString from a byte string
*/
OctetString::OctetString(const uint8_t in[], size_t n) {
   m_data.assign(in, in + n);
}

namespace {

uint8_t odd_parity_of(uint8_t x) {
   uint8_t f = x | 0x01;
   f ^= (f >> 4);
   f ^= (f >> 2);
   f ^= (f >> 1);

   return (x & 0xFE) ^ (f & 0x01);
}

}  // namespace

/*
* Set the parity of each key byte to odd
*/
void OctetString::set_odd_parity() {
   for(size_t j = 0; j != m_data.size(); ++j) {
      m_data[j] = odd_parity_of(m_data[j]);
   }
}

/*
* Hex encode an OctetString
*/
std::string OctetString::to_string() const {
   return hex_encode(m_data.data(), m_data.size());
}

/*
* XOR Operation for OctetStrings
*/
OctetString& OctetString::operator^=(const OctetString& k) {
   if(&k == this) {
      zeroise(m_data);
      return (*this);
   }
   xor_buf(m_data.data(), k.begin(), std::min(length(), k.length()));
   return (*this);
}

/*
* Equality Operation for OctetStrings
*/
bool operator==(const OctetString& s1, const OctetString& s2) {
   return (s1.bits_of() == s2.bits_of());
}

/*
* Unequality Operation for OctetStrings
*/
bool operator!=(const OctetString& s1, const OctetString& s2) {
   return !(s1 == s2);
}

/*
* Append Operation for OctetStrings
*/
OctetString operator+(const OctetString& k1, const OctetString& k2) {
   secure_vector<uint8_t> out;
   out += k1.bits_of();
   out += k2.bits_of();
   return OctetString(out);
}

/*
* XOR Operation for OctetStrings
*/
OctetString operator^(const OctetString& k1, const OctetString& k2) {
   secure_vector<uint8_t> out(std::max(k1.length(), k2.length()));

   copy_mem(out.data(), k1.begin(), k1.length());
   xor_buf(out.data(), k2.begin(), k2.length());
   return OctetString(out);
}

}  // namespace Botan
/*
* Base64 Encoding and Decoding
* (C) 2010,2015,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

namespace {

class Base64 final {
   public:
      static inline std::string name() noexcept { return "base64"; }

      static inline size_t encoding_bytes_in() noexcept { return m_encoding_bytes_in; }

      static inline size_t encoding_bytes_out() noexcept { return m_encoding_bytes_out; }

      static inline size_t decoding_bytes_in() noexcept { return m_encoding_bytes_out; }

      static inline size_t decoding_bytes_out() noexcept { return m_encoding_bytes_in; }

      static inline size_t bits_consumed() noexcept { return m_encoding_bits; }

      static inline size_t remaining_bits_before_padding() noexcept { return m_remaining_bits_before_padding; }

      static inline size_t encode_max_output(size_t input_length) {
         return (round_up(input_length, m_encoding_bytes_in) / m_encoding_bytes_in) * m_encoding_bytes_out;
      }

      static inline size_t decode_max_output(size_t input_length) {
         return (round_up(input_length, m_encoding_bytes_out) * m_encoding_bytes_in) / m_encoding_bytes_out;
      }

      static void encode(char out[8], const uint8_t in[5]) noexcept;

      static uint8_t lookup_binary_value(char input) noexcept;

      static bool check_bad_char(uint8_t bin, char input, bool ignore_ws);

      static void decode(uint8_t* out_ptr, const uint8_t decode_buf[4]) {
         out_ptr[0] = (decode_buf[0] << 2) | (decode_buf[1] >> 4);
         out_ptr[1] = (decode_buf[1] << 4) | (decode_buf[2] >> 2);
         out_ptr[2] = (decode_buf[2] << 6) | decode_buf[3];
      }

      static inline size_t bytes_to_remove(size_t final_truncate) { return final_truncate; }

   private:
      static const size_t m_encoding_bits = 6;
      static const size_t m_remaining_bits_before_padding = 8;

      static const size_t m_encoding_bytes_in = 3;
      static const size_t m_encoding_bytes_out = 4;
};

char lookup_base64_char(uint8_t x) {
   BOTAN_DEBUG_ASSERT(x < 64);

   const auto in_AZ = CT::Mask<uint8_t>::is_lt(x, 26);
   const auto in_09 = CT::Mask<uint8_t>::is_within_range(x, 52, 61);
   const auto eq_plus = CT::Mask<uint8_t>::is_equal(x, 62);
   const auto eq_slash = CT::Mask<uint8_t>::is_equal(x, 63);

   const char c_AZ = 'A' + x;
   const char c_az = 'a' + (x - 26);
   const char c_09 = '0' + (x - 2 * 26);
   const char c_plus = '+';
   const char c_slash = '/';

   char ret = c_az;
   ret = in_AZ.select(c_AZ, ret);
   ret = in_09.select(c_09, ret);
   ret = eq_plus.select(c_plus, ret);
   ret = eq_slash.select(c_slash, ret);

   return ret;
}

//static
void Base64::encode(char out[8], const uint8_t in[5]) noexcept {
   const uint8_t b0 = (in[0] & 0xFC) >> 2;
   const uint8_t b1 = ((in[0] & 0x03) << 4) | (in[1] >> 4);
   const uint8_t b2 = ((in[1] & 0x0F) << 2) | (in[2] >> 6);
   const uint8_t b3 = in[2] & 0x3F;
   out[0] = lookup_base64_char(b0);
   out[1] = lookup_base64_char(b1);
   out[2] = lookup_base64_char(b2);
   out[3] = lookup_base64_char(b3);
}

//static
uint8_t Base64::lookup_binary_value(char input) noexcept {
   const uint8_t c = static_cast<uint8_t>(input);

   const auto is_alpha_upper = CT::Mask<uint8_t>::is_within_range(c, uint8_t('A'), uint8_t('Z'));
   const auto is_alpha_lower = CT::Mask<uint8_t>::is_within_range(c, uint8_t('a'), uint8_t('z'));
   const auto is_decimal = CT::Mask<uint8_t>::is_within_range(c, uint8_t('0'), uint8_t('9'));

   const auto is_plus = CT::Mask<uint8_t>::is_equal(c, uint8_t('+'));
   const auto is_slash = CT::Mask<uint8_t>::is_equal(c, uint8_t('/'));
   const auto is_equal = CT::Mask<uint8_t>::is_equal(c, uint8_t('='));

   const auto is_whitespace =
      CT::Mask<uint8_t>::is_any_of(c, {uint8_t(' '), uint8_t('\t'), uint8_t('\n'), uint8_t('\r')});

   const uint8_t c_upper = c - uint8_t('A');
   const uint8_t c_lower = c - uint8_t('a') + 26;
   const uint8_t c_decim = c - uint8_t('0') + 2 * 26;

   uint8_t ret = 0xFF;  // default value

   ret = is_alpha_upper.select(c_upper, ret);
   ret = is_alpha_lower.select(c_lower, ret);
   ret = is_decimal.select(c_decim, ret);
   ret = is_plus.select(62, ret);
   ret = is_slash.select(63, ret);
   ret = is_equal.select(0x81, ret);
   ret = is_whitespace.select(0x80, ret);

   return ret;
}

//static
bool Base64::check_bad_char(uint8_t bin, char input, bool ignore_ws) {
   if(bin <= 0x3F) {
      return true;
   } else if(!(bin == 0x81 || (bin == 0x80 && ignore_ws))) {
      throw Invalid_Argument(fmt("base64_decode: invalid character '{}'", format_char_for_display(input)));
   }
   return false;
}

}  // namespace

size_t base64_encode(char out[], const uint8_t in[], size_t input_length, size_t& input_consumed, bool final_inputs) {
   return base_encode(Base64(), out, in, input_length, input_consumed, final_inputs);
}

std::string base64_encode(const uint8_t input[], size_t input_length) {
   return base_encode_to_string(Base64(), input, input_length);
}

size_t base64_decode(
   uint8_t out[], const char in[], size_t input_length, size_t& input_consumed, bool final_inputs, bool ignore_ws) {
   return base_decode(Base64(), out, in, input_length, input_consumed, final_inputs, ignore_ws);
}

size_t base64_decode(uint8_t output[], const char input[], size_t input_length, bool ignore_ws) {
   return base_decode_full(Base64(), output, input, input_length, ignore_ws);
}

size_t base64_decode(uint8_t output[], std::string_view input, bool ignore_ws) {
   return base64_decode(output, input.data(), input.length(), ignore_ws);
}

size_t base64_decode(std::span<uint8_t> output, std::string_view input, bool ignore_ws) {
   if(output.size() < base64_decode_max_output(input.size())) {
      throw Invalid_Argument("base64_decode: output buffer is too short");
   }
   return base64_decode(output.data(), input.data(), input.length(), ignore_ws);
}

secure_vector<uint8_t> base64_decode(const char input[], size_t input_length, bool ignore_ws) {
   return base_decode_to_vec<secure_vector<uint8_t>>(Base64(), input, input_length, ignore_ws);
}

secure_vector<uint8_t> base64_decode(std::string_view input, bool ignore_ws) {
   return base64_decode(input.data(), input.size(), ignore_ws);
}

size_t base64_encode_max_output(size_t input_length) {
   return Base64::encode_max_output(input_length);
}

size_t base64_decode_max_output(size_t input_length) {
   return Base64::decode_max_output(input_length);
}

}  // namespace Botan
/*
* Bcrypt Password Hashing
* (C) 2010,2018,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

namespace {

// Bcrypt uses a non-standard base64 alphabet
uint8_t base64_to_bcrypt_encoding(uint8_t c) {
   const auto is_ab = CT::Mask<uint8_t>::is_within_range(c, 'a', 'b');
   const auto is_cz = CT::Mask<uint8_t>::is_within_range(c, 'c', 'z');
   const auto is_CZ = CT::Mask<uint8_t>::is_within_range(c, 'C', 'Z');

   const auto is_01 = CT::Mask<uint8_t>::is_within_range(c, '0', '1');
   const auto is_29 = CT::Mask<uint8_t>::is_within_range(c, '2', '9');

   const auto is_A = CT::Mask<uint8_t>::is_equal(c, 'A');
   const auto is_B = CT::Mask<uint8_t>::is_equal(c, 'B');
   const auto is_plus = CT::Mask<uint8_t>::is_equal(c, '+');
   const auto is_slash = CT::Mask<uint8_t>::is_equal(c, '/');

   uint8_t ret = 0x80;
   ret = is_ab.select(c - 'a' + 'Y', ret);
   ret = is_cz.select(c - 2, ret);
   ret = is_CZ.select(c - 2, ret);
   ret = is_01.select(c - '0' + 'y', ret);
   ret = is_29.select(c - '2' + '0', ret);
   ret = is_A.select('.', ret);
   ret = is_B.select('/', ret);
   ret = is_plus.select('8', ret);
   ret = is_slash.select('9', ret);

   return ret;
}

uint8_t bcrypt_encoding_to_base64(uint8_t c) {
   const auto is_ax = CT::Mask<uint8_t>::is_within_range(c, 'a', 'x');
   const auto is_yz = CT::Mask<uint8_t>::is_within_range(c, 'y', 'z');

   const auto is_AX = CT::Mask<uint8_t>::is_within_range(c, 'A', 'X');
   const auto is_YZ = CT::Mask<uint8_t>::is_within_range(c, 'Y', 'Z');
   const auto is_07 = CT::Mask<uint8_t>::is_within_range(c, '0', '7');

   const auto is_8 = CT::Mask<uint8_t>::is_equal(c, '8');
   const auto is_9 = CT::Mask<uint8_t>::is_equal(c, '9');
   const auto is_dot = CT::Mask<uint8_t>::is_equal(c, '.');
   const auto is_slash = CT::Mask<uint8_t>::is_equal(c, '/');

   uint8_t ret = 0x80;
   ret = is_ax.select(c - 'a' + 'c', ret);
   ret = is_yz.select(c - 'y' + '0', ret);
   ret = is_AX.select(c - 'A' + 'C', ret);
   ret = is_YZ.select(c - 'Y' + 'a', ret);
   ret = is_07.select(c - '0' + '2', ret);
   ret = is_8.select('+', ret);
   ret = is_9.select('/', ret);
   ret = is_dot.select('A', ret);
   ret = is_slash.select('B', ret);

   return ret;
}

std::string bcrypt_base64_encode(const uint8_t input[], size_t length) {
   std::string b64 = base64_encode(input, length);

   while(!b64.empty() && b64[b64.size() - 1] == '=') {
      b64 = b64.substr(0, b64.size() - 1);
   }

   for(size_t i = 0; i != b64.size(); ++i) {
      b64[i] = static_cast<char>(base64_to_bcrypt_encoding(static_cast<uint8_t>(b64[i])));
   }

   return b64;
}

std::vector<uint8_t> bcrypt_base64_decode(std::string_view input) {
   std::string translated;
   for(size_t i = 0; i != input.size(); ++i) {
      char c = bcrypt_encoding_to_base64(static_cast<uint8_t>(input[i]));
      translated.push_back(c);
   }

   return unlock(base64_decode(translated));
}

std::string make_bcrypt(std::string_view pass, const std::vector<uint8_t>& salt, uint16_t work_factor, char version) {
   /*
   * On a 4 GHz Skylake, workfactor == 18 takes about 15 seconds to
   * hash a password. This seems like a reasonable upper bound for the
   * time being.
   * Bcrypt allows up to work factor 31 (2^31 iterations)
   */
   BOTAN_ARG_CHECK(work_factor >= 4 && work_factor <= 18, "Invalid bcrypt work factor");

   alignas(64) static const uint8_t BCRYPT_MAGIC[8 * 3] = {0x4F, 0x72, 0x70, 0x68, 0x65, 0x61, 0x6E, 0x42,
                                                           0x65, 0x68, 0x6F, 0x6C, 0x64, 0x65, 0x72, 0x53,
                                                           0x63, 0x72, 0x79, 0x44, 0x6F, 0x75, 0x62, 0x74};

   Blowfish blowfish;

   secure_vector<uint8_t> pass_with_trailing_null(pass.size() + 1);
   copy_mem(pass_with_trailing_null.data(), cast_char_ptr_to_uint8(pass.data()), pass.length());

   // Include the trailing NULL byte, so we need c_str() not data()
   blowfish.salted_set_key(
      pass_with_trailing_null.data(), pass_with_trailing_null.size(), salt.data(), salt.size(), work_factor);

   std::vector<uint8_t> ctext(BCRYPT_MAGIC, BCRYPT_MAGIC + 8 * 3);

   for(size_t i = 0; i != 64; ++i) {
      blowfish.encrypt_n(ctext.data(), ctext.data(), 3);
   }

   std::string salt_b64 = bcrypt_base64_encode(salt.data(), salt.size());

   std::string work_factor_str = std::to_string(work_factor);
   if(work_factor_str.length() == 1) {
      work_factor_str = "0" + work_factor_str;
   }

   return fmt("$2{}${}${}{}",
              version,
              work_factor_str,
              salt_b64.substr(0, 22),
              bcrypt_base64_encode(ctext.data(), ctext.size() - 1));
}

}  // namespace

std::string generate_bcrypt(std::string_view pass, RandomNumberGenerator& rng, uint16_t work_factor, char version) {
   /*
   2a, 2b and 2y are identical for our purposes because our implementation of 2a
   never had the truncation or signed char bugs in the first place.
   */

   if(version != 'a' && version != 'b' && version != 'y') {
      throw Invalid_Argument("Unknown bcrypt version '" + std::string(1, version) + "'");
   }

   std::vector<uint8_t> salt;
   rng.random_vec(salt, 16);
   return make_bcrypt(pass, salt, work_factor, version);
}

bool check_bcrypt(std::string_view pass, std::string_view hash) {
   if(hash.size() != 60 || hash[0] != '$' || hash[1] != '2' || hash[3] != '$' || hash[6] != '$') {
      return false;
   }

   const char bcrypt_version = hash[2];

   if(bcrypt_version != 'a' && bcrypt_version != 'b' && bcrypt_version != 'y') {
      return false;
   }

   const uint16_t workfactor = to_uint16(hash.substr(4, 2));

   const std::vector<uint8_t> salt = bcrypt_base64_decode(hash.substr(7, 22));
   if(salt.size() != 16) {
      return false;
   }

   const std::string compare = make_bcrypt(pass, salt, workfactor, bcrypt_version);

   return CT::is_equal(cast_char_ptr_to_uint8(hash.data()), cast_char_ptr_to_uint8(compare.data()), compare.size())
      .as_bool();
}

}  // namespace Botan
/*
* Block Ciphers
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#if defined(BOTAN_HAS_AES)
#endif

#if defined(BOTAN_HAS_ARIA)
#endif

#if defined(BOTAN_HAS_BLOWFISH)
#endif

#if defined(BOTAN_HAS_CAMELLIA)
#endif

#if defined(BOTAN_HAS_CAST_128)
#endif

#if defined(BOTAN_HAS_CASCADE)
#endif

#if defined(BOTAN_HAS_DES)
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
#endif

#if defined(BOTAN_HAS_IDEA)
#endif

#if defined(BOTAN_HAS_KUZNYECHIK)
#endif

#if defined(BOTAN_HAS_LION)
#endif

#if defined(BOTAN_HAS_NOEKEON)
#endif

#if defined(BOTAN_HAS_SEED)
#endif

#if defined(BOTAN_HAS_SERPENT)
#endif

#if defined(BOTAN_HAS_SHACAL2)
#endif

#if defined(BOTAN_HAS_SM4)
#endif

#if defined(BOTAN_HAS_TWOFISH)
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
#endif

#if defined(BOTAN_HAS_COMMONCRYPTO)
#endif

namespace Botan {

std::unique_ptr<BlockCipher> BlockCipher::create(std::string_view algo, std::string_view provider) {
#if defined(BOTAN_HAS_COMMONCRYPTO)
   if(provider.empty() || provider == "commoncrypto") {
      if(auto bc = make_commoncrypto_block_cipher(algo))
         return bc;

      if(!provider.empty())
         return nullptr;
   }
#endif

   // TODO: CryptoAPI
   // TODO: /dev/crypto

   // Only base providers from here on out
   if(provider.empty() == false && provider != "base") {
      return nullptr;
   }

#if defined(BOTAN_HAS_AES)
   if(algo == "AES-128") {
      return std::make_unique<AES_128>();
   }

   if(algo == "AES-192") {
      return std::make_unique<AES_192>();
   }

   if(algo == "AES-256") {
      return std::make_unique<AES_256>();
   }
#endif

#if defined(BOTAN_HAS_ARIA)
   if(algo == "ARIA-128") {
      return std::make_unique<ARIA_128>();
   }

   if(algo == "ARIA-192") {
      return std::make_unique<ARIA_192>();
   }

   if(algo == "ARIA-256") {
      return std::make_unique<ARIA_256>();
   }
#endif

#if defined(BOTAN_HAS_SERPENT)
   if(algo == "Serpent") {
      return std::make_unique<Serpent>();
   }
#endif

#if defined(BOTAN_HAS_SHACAL2)
   if(algo == "SHACAL2") {
      return std::make_unique<SHACAL2>();
   }
#endif

#if defined(BOTAN_HAS_TWOFISH)
   if(algo == "Twofish") {
      return std::make_unique<Twofish>();
   }
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
   if(algo == "Threefish-512") {
      return std::make_unique<Threefish_512>();
   }
#endif

#if defined(BOTAN_HAS_BLOWFISH)
   if(algo == "Blowfish") {
      return std::make_unique<Blowfish>();
   }
#endif

#if defined(BOTAN_HAS_CAMELLIA)
   if(algo == "Camellia-128") {
      return std::make_unique<Camellia_128>();
   }

   if(algo == "Camellia-192") {
      return std::make_unique<Camellia_192>();
   }

   if(algo == "Camellia-256") {
      return std::make_unique<Camellia_256>();
   }
#endif

#if defined(BOTAN_HAS_DES)
   if(algo == "DES") {
      return std::make_unique<DES>();
   }

   if(algo == "TripleDES" || algo == "3DES" || algo == "DES-EDE") {
      return std::make_unique<TripleDES>();
   }
#endif

#if defined(BOTAN_HAS_NOEKEON)
   if(algo == "Noekeon") {
      return std::make_unique<Noekeon>();
   }
#endif

#if defined(BOTAN_HAS_CAST_128)
   if(algo == "CAST-128" || algo == "CAST5") {
      return std::make_unique<CAST_128>();
   }
#endif

#if defined(BOTAN_HAS_IDEA)
   if(algo == "IDEA") {
      return std::make_unique<IDEA>();
   }
#endif

#if defined(BOTAN_HAS_KUZNYECHIK)
   if(algo == "Kuznyechik") {
      return std::make_unique<Kuznyechik>();
   }
#endif

#if defined(BOTAN_HAS_SEED)
   if(algo == "SEED") {
      return std::make_unique<SEED>();
   }
#endif

#if defined(BOTAN_HAS_SM4)
   if(algo == "SM4") {
      return std::make_unique<SM4>();
   }
#endif

   const SCAN_Name req(algo);

#if defined(BOTAN_HAS_GOST_28147_89)
   if(req.algo_name() == "GOST-28147-89") {
      return std::make_unique<GOST_28147_89>(req.arg(0, "R3411_94_TestParam"));
   }
#endif

#if defined(BOTAN_HAS_CASCADE)
   if(req.algo_name() == "Cascade" && req.arg_count() == 2) {
      auto c1 = BlockCipher::create(req.arg(0));
      auto c2 = BlockCipher::create(req.arg(1));

      if(c1 && c2) {
         return std::make_unique<Cascade_Cipher>(std::move(c1), std::move(c2));
      }
   }
#endif

#if defined(BOTAN_HAS_LION)
   if(req.algo_name() == "Lion" && req.arg_count_between(2, 3)) {
      auto hash = HashFunction::create(req.arg(0));
      auto stream = StreamCipher::create(req.arg(1));

      if(hash && stream) {
         const size_t block_size = req.arg_as_integer(2, 1024);
         return std::make_unique<Lion>(std::move(hash), std::move(stream), block_size);
      }
   }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
}

//static
std::unique_ptr<BlockCipher> BlockCipher::create_or_throw(std::string_view algo, std::string_view provider) {
   if(auto bc = BlockCipher::create(algo, provider)) {
      return bc;
   }
   throw Lookup_Error("Block cipher", algo, provider);
}

std::vector<std::string> BlockCipher::providers(std::string_view algo) {
   return probe_providers_of<BlockCipher>(algo, {"base", "commoncrypto"});
}

}  // namespace Botan
/*
* Blowfish
* (C) 1999-2011,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

namespace {

// clang-format off

const uint32_t P_INIT[18] = {
   0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89, 0x452821E6,
   0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B
};

const uint32_t S_INIT[1024] = {
   0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99, 0x24A19947,
   0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658,
   0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5, 0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918,
   0xB8DB38EF, 0x8E79DCB0, 0x603A180E, 0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60,
   0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF,
   0x7C72E993, 0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C,
   0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991, 0x487CAC60,
   0x5DEC8032, 0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239,
   0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A, 0x670C9C61, 0xABD388F0, 0x6A51A0D2,
   0xD8542F68, 0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176,
   0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073, 0x401A449F,
   0x56C16AA6, 0x4ED3AA62, 0x363F7706, 0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B,
   0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6,
   0x409F60C4, 0x5E5C9EC2, 0x196A2463, 0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F, 0x6DFC511F, 0x9B30952C,
   0xCC814544, 0xAF5EBD09, 0xBEE3D004, 0xDE334AFD, 0x660F2807, 0x192E4BB3, 0xC0CBA857, 0x45C8740F, 0xD20B5F39,
   0xB9D3FBDB, 0x5579C0BD, 0x1A60320A, 0xD6A100C6, 0x402C7279, 0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8, 0xDB3222F8,
   0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB, 0x323DB5FA, 0xFD238760, 0x53317B48, 0x3E00DF82, 0x9E5C57BB,
   0xCA6F8CA0, 0x1A87562E, 0xDF1769DB, 0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573, 0x695B27B0, 0xBBCA58C8,
   0xE1FFA35D, 0xB8F011A0, 0x10FA3D98, 0xFD2183B8, 0x4AFCB56C, 0x2DD1D35B, 0x9A53E479, 0xB6F84565, 0xD28E49BC,
   0x4BFB9790, 0xE1DDF2DA, 0xA4CB7E33, 0x62FB1341, 0xCEE4C6E8, 0xEF20CADA, 0x36774C01, 0xD07E9EFE, 0x2BF11FB4,
   0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0, 0xD08ED1D0, 0xAFC725E0, 0x8E3C5B2F, 0x8E7594B7, 0x8FF6E2FB,
   0xF2122B64, 0x8888B812, 0x900DF01C, 0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD, 0x2F2F2218, 0xBE0E1777,
   0xEA752DFE, 0x8B021FA1, 0xE5A0CC0F, 0xB56F74E8, 0x18ACF3D6, 0xCE89E299, 0xB4A84FE0, 0xFD13E0B7, 0x7CC43B81,
   0xD2ADA8D9, 0x165FA266, 0x80957705, 0x93CC7314, 0x211A1477, 0xE6AD2065, 0x77B5FA86, 0xC75442F5, 0xFB9D35CF,
   0xEBCDAF0C, 0x7B3E89A0, 0xD6411BD3, 0xAE1E7E49, 0x00250E2D, 0x2071B35E, 0x226800BB, 0x57B8E0AF, 0x2464369B,
   0xF009B91E, 0x5563911D, 0x59DFA6AA, 0x78C14389, 0xD95A537F, 0x207D5BA2, 0x02E5B9C5, 0x83260376, 0x6295CFA9,
   0x11C81968, 0x4E734A41, 0xB3472DCA, 0x7B14A94A, 0x1B510052, 0x9A532915, 0xD60F573F, 0xBC9BC6E4, 0x2B60A476,
   0x81E67400, 0x08BA6FB5, 0x571BE91F, 0xF296EC6B, 0x2A0DD915, 0xB6636521, 0xE7B9F9B6, 0xFF34052E, 0xC5855664,
   0x53B02D5D, 0xA99F8FA1, 0x08BA4799, 0x6E85076A, 0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623, 0xAD6EA6B0,
   0x49A7DF7D, 0x9CEE60B8, 0x8FEDB266, 0xECAA8C71, 0x699A17FF, 0x5664526C, 0xC2B19EE1, 0x193602A5, 0x75094C29,
   0xA0591340, 0xE4183A3E, 0x3F54989A, 0x5B429D65, 0x6B8FE4D6, 0x99F73FD6, 0xA1D29C07, 0xEFE830F5, 0x4D2D38E6,
   0xF0255DC1, 0x4CDD2086, 0x8470EB26, 0x6382E9C6, 0x021ECC5E, 0x09686B3F, 0x3EBAEFC9, 0x3C971814, 0x6B6A70A1,
   0x687F3584, 0x52A0E286, 0xB79C5305, 0xAA500737, 0x3E07841C, 0x7FDEAE5C, 0x8E7D44EC, 0x5716F2B8, 0xB03ADA37,
   0xF0500C0D, 0xF01C1F04, 0x0200B3FF, 0xAE0CF51A, 0x3CB574B2, 0x25837A58, 0xDC0921BD, 0xD19113F9, 0x7CA92FF6,
   0x94324773, 0x22F54701, 0x3AE5E581, 0x37C2DADC, 0xC8B57634, 0x9AF3DDA7, 0xA9446146, 0x0FD0030E, 0xECC8C73E,
   0xA4751E41, 0xE238CD99, 0x3BEA0E2F, 0x3280BBA1, 0x183EB331, 0x4E548B38, 0x4F6DB908, 0x6F420D03, 0xF60A04BF,
   0x2CB81290, 0x24977C79, 0x5679B072, 0xBCAF89AF, 0xDE9A771F, 0xD9930810, 0xB38BAE12, 0xDCCF3F2E, 0x5512721F,
   0x2E6B7124, 0x501ADDE6, 0x9F84CD87, 0x7A584718, 0x7408DA17, 0xBC9F9ABC, 0xE94B7D8C, 0xEC7AEC3A, 0xDB851DFA,
   0x63094366, 0xC464C3D2, 0xEF1C1847, 0x3215D908, 0xDD433B37, 0x24C2BA16, 0x12A14D43, 0x2A65C451, 0x50940002,
   0x133AE4DD, 0x71DFF89E, 0x10314E55, 0x81AC77D6, 0x5F11199B, 0x043556F1, 0xD7A3C76B, 0x3C11183B, 0x5924A509,
   0xF28FE6ED, 0x97F1FBFA, 0x9EBABF2C, 0x1E153C6E, 0x86E34570, 0xEAE96FB1, 0x860E5E0A, 0x5A3E2AB3, 0x771FE71C,
   0x4E3D06FA, 0x2965DCB9, 0x99E71D0F, 0x803E89D6, 0x5266C825, 0x2E4CC978, 0x9C10B36A, 0xC6150EBA, 0x94E2EA78,
   0xA5FC3C53, 0x1E0A2DF4, 0xF2F74EA7, 0x361D2B3D, 0x1939260F, 0x19C27960, 0x5223A708, 0xF71312B6, 0xEBADFE6E,
   0xEAC31F66, 0xE3BC4595, 0xA67BC883, 0xB17F37D1, 0x018CFF28, 0xC332DDEF, 0xBE6C5AA5, 0x65582185, 0x68AB9802,
   0xEECEA50F, 0xDB2F953B, 0x2AEF7DAD, 0x5B6E2F84, 0x1521B628, 0x29076170, 0xECDD4775, 0x619F1510, 0x13CCA830,
   0xEB61BD96, 0x0334FE1E, 0xAA0363CF, 0xB5735C90, 0x4C70A239, 0xD59E9E0B, 0xCBAADE14, 0xEECC86BC, 0x60622CA7,
   0x9CAB5CAB, 0xB2F3846E, 0x648B1EAF, 0x19BDF0CA, 0xA02369B9, 0x655ABB50, 0x40685A32, 0x3C2AB4B3, 0x319EE9D5,
   0xC021B8F7, 0x9B540B19, 0x875FA099, 0x95F7997E, 0x623D7DA8, 0xF837889A, 0x97E32D77, 0x11ED935F, 0x16681281,
   0x0E358829, 0xC7E61FD6, 0x96DEDFA1, 0x7858BA99, 0x57F584A5, 0x1B227263, 0x9B83C3FF, 0x1AC24696, 0xCDB30AEB,
   0x532E3054, 0x8FD948E4, 0x6DBC3128, 0x58EBF2EF, 0x34C6FFEA, 0xFE28ED61, 0xEE7C3C73, 0x5D4A14D9, 0xE864B7E3,
   0x42105D14, 0x203E13E0, 0x45EEE2B6, 0xA3AAABEA, 0xDB6C4F15, 0xFACB4FD0, 0xC742F442, 0xEF6ABBB5, 0x654F3B1D,
   0x41CD2105, 0xD81E799E, 0x86854DC7, 0xE44B476A, 0x3D816250, 0xCF62A1F2, 0x5B8D2646, 0xFC8883A0, 0xC1C7B6A3,
   0x7F1524C3, 0x69CB7492, 0x47848A0B, 0x5692B285, 0x095BBF00, 0xAD19489D, 0x1462B174, 0x23820E00, 0x58428D2A,
   0x0C55F5EA, 0x1DADF43E, 0x233F7061, 0x3372F092, 0x8D937E41, 0xD65FECF1, 0x6C223BDB, 0x7CDE3759, 0xCBEE7460,
   0x4085F2A7, 0xCE77326E, 0xA6078084, 0x19F8509E, 0xE8EFD855, 0x61D99735, 0xA969A7AA, 0xC50C06C2, 0x5A04ABFC,
   0x800BCADC, 0x9E447A2E, 0xC3453484, 0xFDD56705, 0x0E1E9EC9, 0xDB73DBD3, 0x105588CD, 0x675FDA79, 0xE3674340,
   0xC5C43465, 0x713E38D8, 0x3D28F89E, 0xF16DFF20, 0x153E21E7, 0x8FB03D4A, 0xE6E39F2B, 0xDB83ADF7, 0xE93D5A68,
   0x948140F7, 0xF64C261C, 0x94692934, 0x411520F7, 0x7602D4F7, 0xBCF46B2E, 0xD4A20068, 0xD4082471, 0x3320F46A,
   0x43B7D4B7, 0x500061AF, 0x1E39F62E, 0x97244546, 0x14214F74, 0xBF8B8840, 0x4D95FC1D, 0x96B591AF, 0x70F4DDD3,
   0x66A02F45, 0xBFBC09EC, 0x03BD9785, 0x7FAC6DD0, 0x31CB8504, 0x96EB27B3, 0x55FD3941, 0xDA2547E6, 0xABCA0A9A,
   0x28507825, 0x530429F4, 0x0A2C86DA, 0xE9B66DFB, 0x68DC1462, 0xD7486900, 0x680EC0A4, 0x27A18DEE, 0x4F3FFEA2,
   0xE887AD8C, 0xB58CE006, 0x7AF4D6B6, 0xAACE1E7C, 0xD3375FEC, 0xCE78A399, 0x406B2A42, 0x20FE9E35, 0xD9F385B9,
   0xEE39D7AB, 0x3B124E8B, 0x1DC9FAF7, 0x4B6D1856, 0x26A36631, 0xEAE397B2, 0x3A6EFA74, 0xDD5B4332, 0x6841E7F7,
   0xCA7820FB, 0xFB0AF54E, 0xD8FEB397, 0x454056AC, 0xBA489527, 0x55533A3A, 0x20838D87, 0xFE6BA9B7, 0xD096954B,
   0x55A867BC, 0xA1159A58, 0xCCA92963, 0x99E1DB33, 0xA62A4A56, 0x3F3125F9, 0x5EF47E1C, 0x9029317C, 0xFDF8E802,
   0x04272F70, 0x80BB155C, 0x05282CE3, 0x95C11548, 0xE4C66D22, 0x48C1133F, 0xC70F86DC, 0x07F9C9EE, 0x41041F0F,
   0x404779A4, 0x5D886E17, 0x325F51EB, 0xD59BC0D1, 0xF2BCC18F, 0x41113564, 0x257B7834, 0x602A9C60, 0xDFF8E8A3,
   0x1F636C1B, 0x0E12B4C2, 0x02E1329E, 0xAF664FD1, 0xCAD18115, 0x6B2395E0, 0x333E92E1, 0x3B240B62, 0xEEBEB922,
   0x85B2A20E, 0xE6BA0D99, 0xDE720C8C, 0x2DA2F728, 0xD0127845, 0x95B794FD, 0x647D0862, 0xE7CCF5F0, 0x5449A36F,
   0x877D48FA, 0xC39DFD27, 0xF33E8D1E, 0x0A476341, 0x992EFF74, 0x3A6F6EAB, 0xF4F8FD37, 0xA812DC60, 0xA1EBDDF8,
   0x991BE14C, 0xDB6E6B0D, 0xC67B5510, 0x6D672C37, 0x2765D43B, 0xDCD0E804, 0xF1290DC7, 0xCC00FFA3, 0xB5390F92,
   0x690FED0B, 0x667B9FFB, 0xCEDB7D9C, 0xA091CF0B, 0xD9155EA3, 0xBB132F88, 0x515BAD24, 0x7B9479BF, 0x763BD6EB,
   0x37392EB3, 0xCC115979, 0x8026E297, 0xF42E312D, 0x6842ADA7, 0xC66A2B3B, 0x12754CCC, 0x782EF11C, 0x6A124237,
   0xB79251E7, 0x06A1BBE6, 0x4BFB6350, 0x1A6B1018, 0x11CAEDFA, 0x3D25BDD8, 0xE2E1C3C9, 0x44421659, 0x0A121386,
   0xD90CEC6E, 0xD5ABEA2A, 0x64AF674E, 0xDA86A85F, 0xBEBFE988, 0x64E4C3FE, 0x9DBC8057, 0xF0F7C086, 0x60787BF8,
   0x6003604D, 0xD1FD8346, 0xF6381FB0, 0x7745AE04, 0xD736FCCC, 0x83426B33, 0xF01EAB71, 0xB0804187, 0x3C005E5F,
   0x77A057BE, 0xBDE8AE24, 0x55464299, 0xBF582E61, 0x4E58F48F, 0xF2DDFDA2, 0xF474EF38, 0x8789BDC2, 0x5366F9C3,
   0xC8B38E74, 0xB475F255, 0x46FCD9B9, 0x7AEB2661, 0x8B1DDF84, 0x846A0E79, 0x915F95E2, 0x466E598E, 0x20B45770,
   0x8CD55591, 0xC902DE4C, 0xB90BACE1, 0xBB8205D0, 0x11A86248, 0x7574A99E, 0xB77F19B6, 0xE0A9DC09, 0x662D09A1,
   0xC4324633, 0xE85A1F02, 0x09F0BE8C, 0x4A99A025, 0x1D6EFE10, 0x1AB93D1D, 0x0BA5A4DF, 0xA186F20F, 0x2868F169,
   0xDCB7DA83, 0x573906FE, 0xA1E2CE9B, 0x4FCD7F52, 0x50115E01, 0xA70683FA, 0xA002B5C4, 0x0DE6D027, 0x9AF88C27,
   0x773F8641, 0xC3604C06, 0x61A806B5, 0xF0177A28, 0xC0F586E0, 0x006058AA, 0x30DC7D62, 0x11E69ED7, 0x2338EA63,
   0x53C2DD94, 0xC2C21634, 0xBBCBEE56, 0x90BCB6DE, 0xEBFC7DA1, 0xCE591D76, 0x6F05E409, 0x4B7C0188, 0x39720A3D,
   0x7C927C24, 0x86E3725F, 0x724D9DB9, 0x1AC15BB4, 0xD39EB8FC, 0xED545578, 0x08FCA5B5, 0xD83D7CD3, 0x4DAD0FC4,
   0x1E50EF5E, 0xB161E6F8, 0xA28514D9, 0x6C51133C, 0x6FD5C7E7, 0x56E14EC4, 0x362ABFCE, 0xDDC6C837, 0xD79A3234,
   0x92638212, 0x670EFA8E, 0x406000E0, 0x3A39CE37, 0xD3FAF5CF, 0xABC27737, 0x5AC52D1B, 0x5CB0679E, 0x4FA33742,
   0xD3822740, 0x99BC9BBE, 0xD5118E9D, 0xBF0F7315, 0xD62D1C7E, 0xC700C47B, 0xB78C1B6B, 0x21A19045, 0xB26EB1BE,
   0x6A366EB4, 0x5748AB2F, 0xBC946E79, 0xC6A376D2, 0x6549C2C8, 0x530FF8EE, 0x468DDE7D, 0xD5730A1D, 0x4CD04DC6,
   0x2939BBDB, 0xA9BA4650, 0xAC9526E8, 0xBE5EE304, 0xA1FAD5F0, 0x6A2D519A, 0x63EF8CE2, 0x9A86EE22, 0xC089C2B8,
   0x43242EF6, 0xA51E03AA, 0x9CF2D0A4, 0x83C061BA, 0x9BE96A4D, 0x8FE51550, 0xBA645BD6, 0x2826A2F9, 0xA73A3AE1,
   0x4BA99586, 0xEF5562E9, 0xC72FEFD3, 0xF752F7DA, 0x3F046F69, 0x77FA0A59, 0x80E4A915, 0x87B08601, 0x9B09E6AD,
   0x3B3EE593, 0xE990FD5A, 0x9E34D797, 0x2CF0B7D9, 0x022B8B51, 0x96D5AC3A, 0x017DA67D, 0xD1CF3ED6, 0x7C7D2D28,
   0x1F9F25CF, 0xADF2B89B, 0x5AD6B472, 0x5A88F54C, 0xE029AC71, 0xE019A5E6, 0x47B0ACFD, 0xED93FA9B, 0xE8D3C48D,
   0x283B57CC, 0xF8D56629, 0x79132E28, 0x785F0191, 0xED756055, 0xF7960E44, 0xE3D35E8C, 0x15056DD4, 0x88F46DBA,
   0x03A16125, 0x0564F0BD, 0xC3EB9E15, 0x3C9057A2, 0x97271AEC, 0xA93A072A, 0x1B3F6D9B, 0x1E6321F5, 0xF59C66FB,
   0x26DCF319, 0x7533D928, 0xB155FDF5, 0x03563482, 0x8ABA3CBB, 0x28517711, 0xC20AD9F8, 0xABCC5167, 0xCCAD925F,
   0x4DE81751, 0x3830DC8E, 0x379D5862, 0x9320F991, 0xEA7A90C2, 0xFB3E7BCE, 0x5121CE64, 0x774FBE32, 0xA8B6E37E,
   0xC3293D46, 0x48DE5369, 0x6413E680, 0xA2AE0810, 0xDD6DB224, 0x69852DFD, 0x09072166, 0xB39A460A, 0x6445C0DD,
   0x586CDECF, 0x1C20C8AE, 0x5BBEF7DD, 0x1B588D40, 0xCCD2017F, 0x6BB4E3BB, 0xDDA26A7E, 0x3A59FF45, 0x3E350A44,
   0xBCB4CDD5, 0x72EACEA8, 0xFA6484BB, 0x8D6612AE, 0xBF3C6F47, 0xD29BE463, 0x542F5D9E, 0xAEC2771B, 0xF64E6370,
   0x740E0D8D, 0xE75B1357, 0xF8721671, 0xAF537D5D, 0x4040CB08, 0x4EB4E2CC, 0x34D2466A, 0x0115AF84, 0xE1B00428,
   0x95983A1D, 0x06B89FB4, 0xCE6EA048, 0x6F3F3B82, 0x3520AB82, 0x011A1D4B, 0x277227F8, 0x611560B1, 0xE7933FDC,
   0xBB3A792B, 0x344525BD, 0xA08839E1, 0x51CE794B, 0x2F32C9B7, 0xA01FBAC9, 0xE01CC87E, 0xBCC7D1F6, 0xCF0111C3,
   0xA1E8AAC7, 0x1A908749, 0xD44FBD9A, 0xD0DADECB, 0xD50ADA38, 0x0339C32A, 0xC6913667, 0x8DF9317C, 0xE0B12B4F,
   0xF79E59B7, 0x43F5BB3A, 0xF2D519FF, 0x27D9459C, 0xBF97222C, 0x15E6FC2A, 0x0F91FC71, 0x9B941525, 0xFAE59361,
   0xCEB69CEB, 0xC2A86459, 0x12BAA8D1, 0xB6C1075E, 0xE3056A0C, 0x10D25065, 0xCB03A442, 0xE0EC6E0E, 0x1698DB3B,
   0x4C98A0BE, 0x3278E964, 0x9F1F9532, 0xE0D392DF, 0xD3A0342B, 0x8971F21E, 0x1B0A7441, 0x4BA3348C, 0xC5BE7120,
   0xC37632D8, 0xDF359F8D, 0x9B992F2E, 0xE60B6F47, 0x0FE3F11D, 0xE54CDA54, 0x1EDAD891, 0xCE6279CF, 0xCD3E7E6F,
   0x1618B166, 0xFD2C1D05, 0x848FD2C5, 0xF6FB2299, 0xF523F357, 0xA6327623, 0x93A83531, 0x56CCCD02, 0xACF08162,
   0x5A75EBB5, 0x6E163697, 0x88D273CC, 0xDE966292, 0x81B949D0, 0x4C50901B, 0x71C65614, 0xE6C6C7BD, 0x327A140A,
   0x45E1D006, 0xC3F27B9A, 0xC9AA53FD, 0x62A80F00, 0xBB25BFE2, 0x35BDD2F6, 0x71126905, 0xB2040222, 0xB6CBCF7C,
   0xCD769C2B, 0x53113EC0, 0x1640E3D3, 0x38ABBD60, 0x2547ADF0, 0xBA38209C, 0xF746CE76, 0x77AFA1C5, 0x20756060,
   0x85CBFE4E, 0x8AE88DD8, 0x7AAAF9B0, 0x4CF9AA7E, 0x1948C25C, 0x02FB8A8C, 0x01C36AE4, 0xD6EBE1F9, 0x90D4F869,
   0xA65CDEA0, 0x3F09252D, 0xC208E69F, 0xB74E6132, 0xCE77E25B, 0x578FDFE3, 0x3AC372E6
};

// clang-format on

inline uint32_t BFF(uint32_t X, const secure_vector<uint32_t>& S) {
   const uint32_t s0 = S[get_byte<0>(X)];
   const uint32_t s1 = S[get_byte<1>(X) + 256];
   const uint32_t s2 = S[get_byte<2>(X) + 512];
   const uint32_t s3 = S[get_byte<3>(X) + 768];

   return (((s0 + s1) ^ s2) + s3);
}

}  // namespace

/*
* Blowfish Encryption
*/
void Blowfish::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   while(blocks >= 4) {
      uint32_t L0, R0, L1, R1, L2, R2, L3, R3;
      load_be(in, L0, R0, L1, R1, L2, R2, L3, R3);

      for(size_t r = 0; r != 16; r += 2) {
         L0 ^= m_P[r];
         L1 ^= m_P[r];
         L2 ^= m_P[r];
         L3 ^= m_P[r];
         R0 ^= BFF(L0, m_S);
         R1 ^= BFF(L1, m_S);
         R2 ^= BFF(L2, m_S);
         R3 ^= BFF(L3, m_S);

         R0 ^= m_P[r + 1];
         R1 ^= m_P[r + 1];
         R2 ^= m_P[r + 1];
         R3 ^= m_P[r + 1];
         L0 ^= BFF(R0, m_S);
         L1 ^= BFF(R1, m_S);
         L2 ^= BFF(R2, m_S);
         L3 ^= BFF(R3, m_S);
      }

      L0 ^= m_P[16];
      R0 ^= m_P[17];
      L1 ^= m_P[16];
      R1 ^= m_P[17];
      L2 ^= m_P[16];
      R2 ^= m_P[17];
      L3 ^= m_P[16];
      R3 ^= m_P[17];

      store_be(out, R0, L0, R1, L1, R2, L2, R3, L3);

      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
   }

   while(blocks) {
      uint32_t L, R;
      load_be(in, L, R);

      for(size_t r = 0; r != 16; r += 2) {
         L ^= m_P[r];
         R ^= BFF(L, m_S);

         R ^= m_P[r + 1];
         L ^= BFF(R, m_S);
      }

      L ^= m_P[16];
      R ^= m_P[17];

      store_be(out, R, L);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      blocks--;
   }
}

/*
* Blowfish Decryption
*/
void Blowfish::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   while(blocks >= 4) {
      uint32_t L0, R0, L1, R1, L2, R2, L3, R3;
      load_be(in, L0, R0, L1, R1, L2, R2, L3, R3);

      for(size_t r = 17; r != 1; r -= 2) {
         L0 ^= m_P[r];
         L1 ^= m_P[r];
         L2 ^= m_P[r];
         L3 ^= m_P[r];
         R0 ^= BFF(L0, m_S);
         R1 ^= BFF(L1, m_S);
         R2 ^= BFF(L2, m_S);
         R3 ^= BFF(L3, m_S);

         R0 ^= m_P[r - 1];
         R1 ^= m_P[r - 1];
         R2 ^= m_P[r - 1];
         R3 ^= m_P[r - 1];

         L0 ^= BFF(R0, m_S);
         L1 ^= BFF(R1, m_S);
         L2 ^= BFF(R2, m_S);
         L3 ^= BFF(R3, m_S);
      }

      L0 ^= m_P[1];
      R0 ^= m_P[0];
      L1 ^= m_P[1];
      R1 ^= m_P[0];
      L2 ^= m_P[1];
      R2 ^= m_P[0];
      L3 ^= m_P[1];
      R3 ^= m_P[0];

      store_be(out, R0, L0, R1, L1, R2, L2, R3, L3);

      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
   }

   while(blocks) {
      uint32_t L, R;
      load_be(in, L, R);

      for(size_t r = 17; r != 1; r -= 2) {
         L ^= m_P[r];
         R ^= BFF(L, m_S);

         R ^= m_P[r - 1];
         L ^= BFF(R, m_S);
      }

      L ^= m_P[1];
      R ^= m_P[0];

      store_be(out, R, L);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      blocks--;
   }
}

bool Blowfish::has_keying_material() const {
   return !m_P.empty();
}

/*
* Blowfish Key Schedule
*/
void Blowfish::key_schedule(std::span<const uint8_t> key) {
   m_P.resize(18);
   copy_mem(m_P.data(), P_INIT, 18);

   m_S.resize(1024);
   copy_mem(m_S.data(), S_INIT, 1024);

   key_expansion(key.data(), key.size(), nullptr, 0);
}

void Blowfish::key_expansion(const uint8_t key[], size_t length, const uint8_t salt[], size_t salt_length) {
   BOTAN_ASSERT_NOMSG(salt_length % 4 == 0);

   for(size_t i = 0, j = 0; i != 18; ++i, j += 4) {
      m_P[i] ^= make_uint32(key[(j) % length], key[(j + 1) % length], key[(j + 2) % length], key[(j + 3) % length]);
   }

   const size_t P_salt_offset = (salt_length > 0) ? 18 % (salt_length / 4) : 0;

   uint32_t L = 0, R = 0;
   generate_sbox(m_P, L, R, salt, salt_length, 0);
   generate_sbox(m_S, L, R, salt, salt_length, P_salt_offset);
}

/*
* Modified key schedule used for bcrypt password hashing
*/
void Blowfish::salted_set_key(
   const uint8_t key[], size_t length, const uint8_t salt[], size_t salt_length, size_t workfactor, bool salt_first) {
   BOTAN_ARG_CHECK(salt_length > 0 && salt_length % 4 == 0, "Invalid salt length for Blowfish salted key schedule");

   if(length > 72) {
      // Truncate longer passwords to the 72 char bcrypt limit
      length = 72;
   }

   m_P.resize(18);
   copy_mem(m_P.data(), P_INIT, 18);

   m_S.resize(1024);
   copy_mem(m_S.data(), S_INIT, 1024);
   key_expansion(key, length, salt, salt_length);

   if(workfactor > 0) {
      const size_t rounds = static_cast<size_t>(1) << workfactor;

      for(size_t r = 0; r != rounds; ++r) {
         if(salt_first) {
            key_expansion(salt, salt_length, nullptr, 0);
            key_expansion(key, length, nullptr, 0);
         } else {
            key_expansion(key, length, nullptr, 0);
            key_expansion(salt, salt_length, nullptr, 0);
         }
      }
   }
}

/*
* Generate one of the Sboxes
*/
void Blowfish::generate_sbox(secure_vector<uint32_t>& box,
                             uint32_t& L,
                             uint32_t& R,
                             const uint8_t salt[],
                             size_t salt_length,
                             size_t salt_off) const {
   for(size_t i = 0; i != box.size(); i += 2) {
      if(salt_length > 0) {
         L ^= load_be<uint32_t>(salt, (i + salt_off) % (salt_length / 4));
         R ^= load_be<uint32_t>(salt, (i + salt_off + 1) % (salt_length / 4));
      }

      for(size_t r = 0; r != 16; r += 2) {
         L ^= m_P[r];
         R ^= BFF(L, m_S);

         R ^= m_P[r + 1];
         L ^= BFF(R, m_S);
      }

      uint32_t T = R;
      R = L ^ m_P[16];
      L = T ^ m_P[17];
      box[i] = L;
      box[i + 1] = R;
   }
}

/*
* Clear memory of sensitive data
*/
void Blowfish::clear() {
   zap(m_P);
   zap(m_S);
}

}  // namespace Botan
/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <ostream>

namespace Botan {

bool CPUID::has_simd_32() {
#if defined(BOTAN_TARGET_SUPPORTS_SSE2)
   return CPUID::has_sse2();
#elif defined(BOTAN_TARGET_SUPPORTS_ALTIVEC)
   return CPUID::has_altivec();
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
   return CPUID::has_neon();
#else
   return true;
#endif
}

//static
std::string CPUID::to_string() {
   std::vector<std::string> flags;

   auto append_fn = [&](bool flag, const char* flag_name) {
      if(flag) {
         flags.push_back(flag_name);
      }
   };

   // NOLINTNEXTLINE(*-macro-usage)
#define CPUID_PRINT(flag) append_fn(has_##flag(), #flag)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   CPUID_PRINT(rdtsc);

   CPUID_PRINT(sse2);
   CPUID_PRINT(ssse3);
   CPUID_PRINT(avx2);

   CPUID_PRINT(bmi2);
   CPUID_PRINT(adx);

   CPUID_PRINT(aes_ni);
   CPUID_PRINT(clmul);
   CPUID_PRINT(rdrand);
   CPUID_PRINT(rdseed);
   CPUID_PRINT(intel_sha);

   CPUID_PRINT(avx512);
   CPUID_PRINT(avx512_aes);
   CPUID_PRINT(avx512_clmul);
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   CPUID_PRINT(altivec);
   CPUID_PRINT(power_crypto);
   CPUID_PRINT(darn_rng);
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   CPUID_PRINT(neon);
   CPUID_PRINT(arm_sve);

   CPUID_PRINT(arm_sha1);
   CPUID_PRINT(arm_sha2);
   CPUID_PRINT(arm_aes);
   CPUID_PRINT(arm_pmull);
   CPUID_PRINT(arm_sha2_512);
   CPUID_PRINT(arm_sha3);
   CPUID_PRINT(arm_sm3);
   CPUID_PRINT(arm_sm4);
#else
   BOTAN_UNUSED(append_fn);
#endif

#undef CPUID_PRINT

   return string_join(flags, ' ');
}

//static
void CPUID::initialize() {
   state() = CPUID_Data();
}

namespace {

// Returns true if big-endian
bool runtime_check_if_big_endian() {
   // Check runtime endian
   const uint32_t endian32 = 0x01234567;
   const uint8_t* e8 = reinterpret_cast<const uint8_t*>(&endian32);

   bool is_big_endian = false;

   if(e8[0] == 0x01 && e8[1] == 0x23 && e8[2] == 0x45 && e8[3] == 0x67) {
      is_big_endian = true;
   } else if(e8[0] == 0x67 && e8[1] == 0x45 && e8[2] == 0x23 && e8[3] == 0x01) {
      is_big_endian = false;
   } else {
      throw Internal_Error("Unexpected endian at runtime, neither big nor little");
   }

   // If we were compiled with a known endian, verify it matches at runtime
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   BOTAN_ASSERT(!is_big_endian, "Build and runtime endian match");
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   BOTAN_ASSERT(is_big_endian, "Build and runtime endian match");
#endif

   return is_big_endian;
}

}  // namespace

CPUID::CPUID_Data::CPUID_Data() {
   m_processor_features = 0;

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY) || defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY) || \
   defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   m_processor_features = detect_cpu_features();

#endif

   m_processor_features |= CPUID::CPUID_INITIALIZED_BIT;

   if(runtime_check_if_big_endian()) {
      m_processor_features |= CPUID::CPUID_IS_BIG_ENDIAN_BIT;
   }

   std::string clear_cpuid_env;
   if(OS::read_env_variable(clear_cpuid_env, "BOTAN_CLEAR_CPUID")) {
      for(const auto& cpuid : split_on(clear_cpuid_env, ',')) {
         for(auto& bit : CPUID::bit_from_string(cpuid)) {
            const uint32_t cleared = ~static_cast<uint32_t>(bit);
            m_processor_features &= cleared;
         }
      }
   }
}

std::vector<CPUID::CPUID_bits> CPUID::bit_from_string(std::string_view tok) {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   if(tok == "sse2" || tok == "simd") {
      return {CPUID::CPUID_SSE2_BIT};
   }
   if(tok == "ssse3") {
      return {CPUID::CPUID_SSSE3_BIT};
   }
   // aes_ni is the string printed on the console when running "botan cpuid"
   if(tok == "aesni" || tok == "aes_ni") {
      return {CPUID::CPUID_AESNI_BIT};
   }
   if(tok == "clmul") {
      return {CPUID::CPUID_CLMUL_BIT};
   }
   if(tok == "avx2") {
      return {CPUID::CPUID_AVX2_BIT};
   }
   if(tok == "avx512") {
      return {CPUID::CPUID_AVX512_BIT};
   }
   // there were two if statements testing "sha" and "intel_sha" separately; combined
   if(tok == "sha" || tok == "intel_sha") {
      return {CPUID::CPUID_SHA_BIT};
   }
   if(tok == "rdtsc") {
      return {CPUID::CPUID_RDTSC_BIT};
   }
   if(tok == "bmi2") {
      return {CPUID::CPUID_BMI_BIT};
   }
   if(tok == "adx") {
      return {CPUID::CPUID_ADX_BIT};
   }
   if(tok == "rdrand") {
      return {CPUID::CPUID_RDRAND_BIT};
   }
   if(tok == "rdseed") {
      return {CPUID::CPUID_RDSEED_BIT};
   }
   if(tok == "avx512_aes") {
      return {CPUID::CPUID_AVX512_AES_BIT};
   }
   if(tok == "avx512_clmul") {
      return {CPUID::CPUID_AVX512_CLMUL_BIT};
   }

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   if(tok == "altivec" || tok == "simd")
      return {CPUID::CPUID_ALTIVEC_BIT};
   if(tok == "power_crypto")
      return {CPUID::CPUID_POWER_CRYPTO_BIT};
   if(tok == "darn_rng")
      return {CPUID::CPUID_DARN_BIT};

#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   if(tok == "neon" || tok == "simd")
      return {CPUID::CPUID_ARM_NEON_BIT};
   if(tok == "arm_sve")
      return {CPUID::CPUID_ARM_SVE_BIT};
   if(tok == "armv8sha1" || tok == "arm_sha1")
      return {CPUID::CPUID_ARM_SHA1_BIT};
   if(tok == "armv8sha2" || tok == "arm_sha2")
      return {CPUID::CPUID_ARM_SHA2_BIT};
   if(tok == "armv8aes" || tok == "arm_aes")
      return {CPUID::CPUID_ARM_AES_BIT};
   if(tok == "armv8pmull" || tok == "arm_pmull")
      return {CPUID::CPUID_ARM_PMULL_BIT};
   if(tok == "armv8sha3" || tok == "arm_sha3")
      return {CPUID::CPUID_ARM_SHA3_BIT};
   if(tok == "armv8sha2_512" || tok == "arm_sha2_512")
      return {CPUID::CPUID_ARM_SHA2_512_BIT};
   if(tok == "armv8sm3" || tok == "arm_sm3")
      return {CPUID::CPUID_ARM_SM3_BIT};
   if(tok == "armv8sm4" || tok == "arm_sm4")
      return {CPUID::CPUID_ARM_SM4_BIT};

#else
   BOTAN_UNUSED(tok);
#endif

   return {};
}

}  // namespace Botan
/*
* Runtime CPU detection for Aarch64
* (C) 2009,2010,2013,2017,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_ARCH_IS_ARM64)


   #if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
      #include <sys/sysctl.h>
      #include <sys/types.h>
   #endif

namespace Botan {

   #if defined(BOTAN_TARGET_OS_IS_MACOS)
namespace {

bool sysctlbyname_has_feature(const char* feature_name) {
   unsigned int feature;
   size_t size = sizeof(feature);
   ::sysctlbyname(feature_name, &feature, &size, nullptr, 0);
   return (feature == 1);
}

}  // namespace
   #endif

uint32_t CPUID::CPUID_Data::detect_cpu_features() {
   uint32_t detected_features = 0;

   #if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   /*
   * On systems with getauxval these bits should normally be defined
   * in bits/auxv.h but some buggy? glibc installs seem to miss them.
   * These following values are all fixed, for the Linux ELF format,
   * so we just hardcode them in ARM_hwcap_bit enum.
   */

   enum ARM_hwcap_bit {
      NEON_bit = (1 << 1),
      AES_bit = (1 << 3),
      PMULL_bit = (1 << 4),
      SHA1_bit = (1 << 5),
      SHA2_bit = (1 << 6),
      SHA3_bit = (1 << 17),
      SM3_bit = (1 << 18),
      SM4_bit = (1 << 19),
      SHA2_512_bit = (1 << 21),
      SVE_bit = (1 << 22),

      ARCH_hwcap = 16,  // AT_HWCAP
   };

   const unsigned long hwcap = OS::get_auxval(ARM_hwcap_bit::ARCH_hwcap);
   if(hwcap & ARM_hwcap_bit::NEON_bit) {
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;
      if(hwcap & ARM_hwcap_bit::AES_bit)
         detected_features |= CPUID::CPUID_ARM_AES_BIT;
      if(hwcap & ARM_hwcap_bit::PMULL_bit)
         detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
      if(hwcap & ARM_hwcap_bit::SHA1_bit)
         detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
      if(hwcap & ARM_hwcap_bit::SHA2_bit)
         detected_features |= CPUID::CPUID_ARM_SHA2_BIT;
      if(hwcap & ARM_hwcap_bit::SHA3_bit)
         detected_features |= CPUID::CPUID_ARM_SHA3_BIT;
      if(hwcap & ARM_hwcap_bit::SM3_bit)
         detected_features |= CPUID::CPUID_ARM_SM3_BIT;
      if(hwcap & ARM_hwcap_bit::SM4_bit)
         detected_features |= CPUID::CPUID_ARM_SM4_BIT;
      if(hwcap & ARM_hwcap_bit::SHA2_512_bit)
         detected_features |= CPUID::CPUID_ARM_SHA2_512_BIT;
      if(hwcap & ARM_hwcap_bit::SVE_bit)
         detected_features |= CPUID::CPUID_ARM_SVE_BIT;
   }

   #elif defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)

   // All 64-bit Apple ARM chips have NEON, AES, and SHA support
   detected_features |= CPUID::CPUID_ARM_NEON_BIT;
   detected_features |= CPUID::CPUID_ARM_AES_BIT;
   detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
   detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
   detected_features |= CPUID::CPUID_ARM_SHA2_BIT;

      #if defined(BOTAN_TARGET_OS_IS_MACOS)
   if(sysctlbyname_has_feature("hw.optional.armv8_2_sha3"))
      detected_features |= CPUID::CPUID_ARM_SHA3_BIT;
   if(sysctlbyname_has_feature("hw.optional.armv8_2_sha512"))
      detected_features |= CPUID::CPUID_ARM_SHA2_512_BIT;
      #endif

   #elif defined(BOTAN_USE_GCC_INLINE_ASM)

   /*
   No getauxval API available, fall back on probe functions. We only
   bother with Aarch64 here to simplify the code and because going to
   extreme contortions to detect NEON on devices that probably don't
   support it doesn't seem worthwhile.

   NEON registers v0-v7 are caller saved in Aarch64
   */

   auto neon_probe = []() noexcept -> int {
      asm("and v0.16b, v0.16b, v0.16b");
      return 1;
   };
   auto aes_probe = []() noexcept -> int {
      asm(".word 0x4e284800");
      return 1;
   };
   auto pmull_probe = []() noexcept -> int {
      asm(".word 0x0ee0e000");
      return 1;
   };
   auto sha1_probe = []() noexcept -> int {
      asm(".word 0x5e280800");
      return 1;
   };
   auto sha2_probe = []() noexcept -> int {
      asm(".word 0x5e282800");
      return 1;
   };
   auto sha512_probe = []() noexcept -> int {
      asm(".long 0xcec08000");
      return 1;
   };

   // Only bother running the crypto detection if we found NEON

   if(OS::run_cpu_instruction_probe(neon_probe) == 1) {
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;

      if(OS::run_cpu_instruction_probe(aes_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_AES_BIT;
      if(OS::run_cpu_instruction_probe(pmull_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
      if(OS::run_cpu_instruction_probe(sha1_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
      if(OS::run_cpu_instruction_probe(sha2_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA2_BIT;
      if(OS::run_cpu_instruction_probe(sha512_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA2_512_BIT;
   }

   #endif

   return detected_features;
}

}  // namespace Botan

#endif
/*
* Runtime CPU detection for 32-bit ARM
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_ARCH_IS_ARM32)


namespace Botan {

uint32_t CPUID::CPUID_Data::detect_cpu_features() {
   uint32_t detected_features = 0;

   #if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   /*
   * On systems with getauxval these bits should normally be defined
   * in bits/auxv.h but some buggy? glibc installs seem to miss them.
   * These following values are all fixed, for the Linux ELF format,
   * so we just hardcode them in ARM_hwcap_bit enum.
   */

   enum ARM_hwcap_bit {
      NEON_bit = (1 << 12),
      AES_bit = (1 << 0),
      PMULL_bit = (1 << 1),
      SHA1_bit = (1 << 2),
      SHA2_bit = (1 << 3),

      ARCH_hwcap_neon = 16,    // AT_HWCAP
      ARCH_hwcap_crypto = 26,  // AT_HWCAP2
   };

   const unsigned long hwcap_neon = OS::get_auxval(ARM_hwcap_bit::ARCH_hwcap_neon);
   if(hwcap_neon & ARM_hwcap_bit::NEON_bit) {
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;

      const unsigned long hwcap_crypto = OS::get_auxval(ARM_hwcap_bit::ARCH_hwcap_crypto);
      if(hwcap_crypto & ARM_hwcap_bit::AES_bit)
         detected_features |= CPUID::CPUID_ARM_AES_BIT;
      if(hwcap_crypto & ARM_hwcap_bit::PMULL_bit)
         detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
      if(hwcap_crypto & ARM_hwcap_bit::SHA1_bit)
         detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
      if(hwcap_crypto & ARM_hwcap_bit::SHA2_bit)
         detected_features |= CPUID::CPUID_ARM_SHA2_BIT;
   }
   #endif

   return detected_features;
}

}  // namespace Botan

#endif
/*
* Runtime CPU detection for POWER/PowerPC
* (C) 2009,2010,2013,2017,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

namespace Botan {

uint32_t CPUID::CPUID_Data::detect_cpu_features() {
   uint32_t detected_features = 0;

   #if(defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_HAS_ELF_AUX_INFO)) && \
      defined(BOTAN_TARGET_ARCH_IS_PPC64)

   enum PPC_hwcap_bit {
      ALTIVEC_bit = (1 << 28),
      CRYPTO_bit = (1 << 25),
      DARN_bit = (1 << 21),

      ARCH_hwcap_altivec = 16,  // AT_HWCAP
      ARCH_hwcap_crypto = 26,   // AT_HWCAP2
   };

   const unsigned long hwcap_altivec = OS::get_auxval(PPC_hwcap_bit::ARCH_hwcap_altivec);
   if(hwcap_altivec & PPC_hwcap_bit::ALTIVEC_bit) {
      detected_features |= CPUID::CPUID_ALTIVEC_BIT;

      const unsigned long hwcap_crypto = OS::get_auxval(PPC_hwcap_bit::ARCH_hwcap_crypto);
      if(hwcap_crypto & PPC_hwcap_bit::CRYPTO_bit)
         detected_features |= CPUID::CPUID_POWER_CRYPTO_BIT;
      if(hwcap_crypto & PPC_hwcap_bit::DARN_bit)
         detected_features |= CPUID::CPUID_DARN_BIT;
   }

   #else

   auto vmx_probe = []() noexcept -> int {
      asm("vor 0, 0, 0");
      return 1;
   };

   if(OS::run_cpu_instruction_probe(vmx_probe) == 1) {
      detected_features |= CPUID::CPUID_ALTIVEC_BIT;

      #if defined(BOTAN_TARGET_ARCH_IS_PPC64)
      auto vcipher_probe = []() noexcept -> int {
         asm("vcipher 0, 0, 0");
         return 1;
      };

      if(OS::run_cpu_instruction_probe(vcipher_probe) == 1)
         detected_features |= CPUID::CPUID_POWER_CRYPTO_BIT;

      auto darn_probe = []() noexcept -> int {
         uint64_t output = 0;
         asm volatile("darn %0, 1" : "=r"(output));
         return (~output) != 0;
      };

      if(OS::run_cpu_instruction_probe(darn_probe) == 1)
         detected_features |= CPUID::CPUID_DARN_BIT;
      #endif
   }

   #endif

   return detected_features;
}

}  // namespace Botan

#endif
/*
* Runtime CPU detection for x86
* (C) 2009,2010,2013,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   #include <immintrin.h>

   #if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
      #include <intrin.h>
   #elif defined(BOTAN_BUILD_COMPILER_IS_INTEL)
      #include <ia32intrin.h>
   #elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
      #include <cpuid.h>
   #endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

namespace {

void invoke_cpuid(uint32_t type, uint32_t out[4]) {
   #if defined(BOTAN_BUILD_COMPILER_IS_MSVC) || defined(BOTAN_BUILD_COMPILER_IS_INTEL)
   __cpuid((int*)out, type);

   #elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
   __get_cpuid(type, out, out + 1, out + 2, out + 3);

   #elif defined(BOTAN_USE_GCC_INLINE_ASM)
   asm("cpuid\n\t" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "0"(type));

   #else
      #warning "No way of calling x86 cpuid instruction for this compiler"
   clear_mem(out, 4);
   #endif
}

BOTAN_FUNC_ISA("xsave") uint64_t xgetbv() {
   return _xgetbv(0);
}

void invoke_cpuid_sublevel(uint32_t type, uint32_t level, uint32_t out[4]) {
   #if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   __cpuidex((int*)out, type, level);

   #elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
   __cpuid_count(type, level, out[0], out[1], out[2], out[3]);

   #elif defined(BOTAN_USE_GCC_INLINE_ASM)
   asm("cpuid\n\t" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "0"(type), "2"(level));

   #else
      #warning "No way of calling x86 cpuid instruction for this compiler"
   clear_mem(out, 4);
   #endif
}

}  // namespace

uint32_t CPUID::CPUID_Data::detect_cpu_features() {
   uint32_t features_detected = 0;
   uint32_t cpuid[4] = {0};
   bool has_os_ymm_support = false;
   bool has_os_zmm_support = false;

   // CPUID 0: vendor identification, max sublevel
   invoke_cpuid(0, cpuid);

   const uint32_t max_supported_sublevel = cpuid[0];

   if(max_supported_sublevel >= 1) {
      // CPUID 1: feature bits
      invoke_cpuid(1, cpuid);
      const uint64_t flags0 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[3];

      enum x86_CPUID_1_bits : uint64_t {
         RDTSC = (1ULL << 4),
         SSE2 = (1ULL << 26),
         CLMUL = (1ULL << 33),
         SSSE3 = (1ULL << 41),
         AESNI = (1ULL << 57),
         OSXSAVE = (1ULL << 59),
         AVX = (1ULL << 60),
         RDRAND = (1ULL << 62)
      };

      if(flags0 & x86_CPUID_1_bits::RDTSC) {
         features_detected |= CPUID::CPUID_RDTSC_BIT;
      }
      if(flags0 & x86_CPUID_1_bits::SSE2) {
         features_detected |= CPUID::CPUID_SSE2_BIT;
      }
      if(flags0 & x86_CPUID_1_bits::CLMUL) {
         features_detected |= CPUID::CPUID_CLMUL_BIT;
      }
      if(flags0 & x86_CPUID_1_bits::SSSE3) {
         features_detected |= CPUID::CPUID_SSSE3_BIT;
      }
      if(flags0 & x86_CPUID_1_bits::AESNI) {
         features_detected |= CPUID::CPUID_AESNI_BIT;
      }
      if(flags0 & x86_CPUID_1_bits::RDRAND) {
         features_detected |= CPUID::CPUID_RDRAND_BIT;
      }

      if((flags0 & x86_CPUID_1_bits::AVX) && (flags0 & x86_CPUID_1_bits::OSXSAVE)) {
         const uint64_t xcr_flags = xgetbv();
         if((xcr_flags & 0x6) == 0x6) {
            has_os_ymm_support = true;
            has_os_zmm_support = (xcr_flags & 0xE0) == 0xE0;
         }
      }
   }

   if(max_supported_sublevel >= 7) {
      clear_mem(cpuid, 4);
      invoke_cpuid_sublevel(7, 0, cpuid);

      enum x86_CPUID_7_bits : uint64_t {
         BMI1 = (1ULL << 3),
         AVX2 = (1ULL << 5),
         BMI2 = (1ULL << 8),
         AVX512_F = (1ULL << 16),
         AVX512_DQ = (1ULL << 17),
         RDSEED = (1ULL << 18),
         ADX = (1ULL << 19),
         AVX512_IFMA = (1ULL << 21),
         SHA = (1ULL << 29),
         AVX512_BW = (1ULL << 30),
         AVX512_VL = (1ULL << 31),
         AVX512_VBMI = (1ULL << 33),
         AVX512_VBMI2 = (1ULL << 38),
         AVX512_VAES = (1ULL << 41),
         AVX512_VCLMUL = (1ULL << 42),
         AVX512_VBITALG = (1ULL << 44),
      };

      const uint64_t flags7 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[1];

      if((flags7 & x86_CPUID_7_bits::AVX2) && has_os_ymm_support) {
         features_detected |= CPUID::CPUID_AVX2_BIT;
      }
      if(flags7 & x86_CPUID_7_bits::RDSEED) {
         features_detected |= CPUID::CPUID_RDSEED_BIT;
      }
      if(flags7 & x86_CPUID_7_bits::ADX) {
         features_detected |= CPUID::CPUID_ADX_BIT;
      }
      if(flags7 & x86_CPUID_7_bits::SHA) {
         features_detected |= CPUID::CPUID_SHA_BIT;
      }

      /*
      We only set the BMI bit if both BMI1 and BMI2 are supported, since
      typically we want to use both extensions in the same code.
      */
      if((flags7 & x86_CPUID_7_bits::BMI1) && (flags7 & x86_CPUID_7_bits::BMI2)) {
         features_detected |= CPUID::CPUID_BMI_BIT;
      }

      if((flags7 & x86_CPUID_7_bits::AVX512_F) && has_os_zmm_support) {
         const uint64_t AVX512_PROFILE_FLAGS = x86_CPUID_7_bits::AVX512_F | x86_CPUID_7_bits::AVX512_DQ |
                                               x86_CPUID_7_bits::AVX512_IFMA | x86_CPUID_7_bits::AVX512_BW |
                                               x86_CPUID_7_bits::AVX512_VL | x86_CPUID_7_bits::AVX512_VBMI |
                                               x86_CPUID_7_bits::AVX512_VBMI2 | x86_CPUID_7_bits::AVX512_VBITALG;

         /*
         We only enable AVX512 support if all of the above flags are available

         This is more than we strictly need for most uses, however it also has
         the effect of preventing execution of AVX512 codepaths on cores that
         have serious downclocking problems when AVX512 code executes,
         especially Intel Skylake.

         VBMI2/VBITALG are the key flags here as they restrict us to Intel Ice
         Lake/Rocket Lake, or AMD Zen4, all of which do not have penalties for
         executing AVX512.

         There is nothing stopping some future processor from supporting the
         above flags and having AVX512 penalties, but maybe you should not have
         bought such a processor.
         */
         if((flags7 & AVX512_PROFILE_FLAGS) == AVX512_PROFILE_FLAGS) {
            features_detected |= CPUID::CPUID_AVX512_BIT;

            if(flags7 & x86_CPUID_7_bits::AVX512_VAES) {
               features_detected |= CPUID::CPUID_AVX512_AES_BIT;
            }
            if(flags7 & x86_CPUID_7_bits::AVX512_VCLMUL) {
               features_detected |= CPUID::CPUID_AVX512_CLMUL_BIT;
            }
         }
      }
   }

   /*
   * If we don't have access to CPUID, we can still safely assume that
   * any x86-64 processor has SSE2 and RDTSC
   */
   #if defined(BOTAN_TARGET_ARCH_IS_X86_64)
   if(features_detected == 0) {
      features_detected |= CPUID::CPUID_SSE2_BIT;
      features_detected |= CPUID::CPUID_RDTSC_BIT;
   }
   #endif

   return features_detected;
}

#endif

}  // namespace Botan
/*
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <sstream>

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <dlfcn.h>
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
#endif

namespace Botan {

namespace {

void raise_runtime_loader_exception(std::string_view lib_name, const char* msg) {
   std::ostringstream err;
   err << "Failed to load " << lib_name << ": ";
   if(msg) {
      err << msg;
   } else {
      err << "Unknown error";
   }

   throw System_Error(err.str(), 0);
}

}  // namespace

Dynamically_Loaded_Library::Dynamically_Loaded_Library(std::string_view library) : m_lib_name(library), m_lib(nullptr) {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   m_lib = ::dlopen(m_lib_name.c_str(), RTLD_LAZY);

   if(!m_lib) {
      raise_runtime_loader_exception(m_lib_name, ::dlerror());
   }

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   m_lib = ::LoadLibraryA(m_lib_name.c_str());

   if(!m_lib)
      raise_runtime_loader_exception(m_lib_name, "LoadLibrary failed");
#endif

   if(!m_lib) {
      raise_runtime_loader_exception(m_lib_name, "Dynamic load not supported");
   }
}

Dynamically_Loaded_Library::~Dynamically_Loaded_Library() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   ::dlclose(m_lib);
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   ::FreeLibrary(reinterpret_cast<HMODULE>(m_lib));
#endif
}

void* Dynamically_Loaded_Library::resolve_symbol(const std::string& symbol) {
   void* addr = nullptr;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   addr = ::dlsym(m_lib, symbol.c_str());
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   addr = reinterpret_cast<void*>(::GetProcAddress(reinterpret_cast<HMODULE>(m_lib), symbol.c_str()));
#endif

   if(!addr) {
      throw Invalid_Argument(fmt("Failed to resolve symbol {} in {}", symbol, m_lib_name));
   }

   return addr;
}

}  // namespace Botan
/*
* Entropy Source Polling
* (C) 2008-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#if defined(BOTAN_HAS_SYSTEM_RNG)
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_SYSTEM_RNG)

class System_RNG_EntropySource final : public Entropy_Source {
   public:
      size_t poll(RandomNumberGenerator& rng) override {
         const size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS;
         rng.reseed_from_rng(system_rng(), poll_bits);
         return poll_bits;
      }

      std::string name() const override { return "system_rng"; }
};

#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)

class Processor_RNG_EntropySource final : public Entropy_Source {
   public:
      size_t poll(RandomNumberGenerator& rng) override {
         /*
         * Intel's documentation for RDRAND at
         * https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide
         * claims that software can guarantee a reseed event by polling enough data:
         * "There is an upper bound of 511 samples per seed in the implementation
         * where samples are 128 bits in size and can provide two 64-bit random
         * numbers each."
         *
         * By requesting 65536 bits we are asking for 512 samples and thus are assured
         * that at some point in producing the output, at least one reseed of the
         * internal state will occur.
         *
         * The reseeding conditions of the POWER and ARM processor RNGs are not known
         * but probably work in a somewhat similar manner. The exact amount requested
         * may be tweaked if and when such conditions become publically known.
         */
         const size_t poll_bits = 65536;
         rng.reseed_from_rng(m_hwrng, poll_bits);
         // Avoid trusting a black box, don't count this as contributing entropy:
         return 0;
      }

      std::string name() const override { return m_hwrng.name(); }

   private:
      Processor_RNG m_hwrng;
};

#endif

}  // namespace

std::unique_ptr<Entropy_Source> Entropy_Source::create(std::string_view name) {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   if(name == "system_rng") {
      return std::make_unique<System_RNG_EntropySource>();
   }
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   if(name == "hwrng") {
      if(Processor_RNG::available()) {
         return std::make_unique<Processor_RNG_EntropySource>();
      }
   }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
   if(name == "rdseed") {
      return std::make_unique<Intel_Rdseed>();
   }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
   if(name == "getentropy") {
      return std::make_unique<Getentropy>();
   }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
   if(name == "system_stats") {
      return std::make_unique<Win32_EntropySource>();
   }
#endif

   BOTAN_UNUSED(name);
   return nullptr;
}

void Entropy_Sources::add_source(std::unique_ptr<Entropy_Source> src) {
   if(src) {
      m_srcs.push_back(std::move(src));
   }
}

std::vector<std::string> Entropy_Sources::enabled_sources() const {
   std::vector<std::string> sources;
   sources.reserve(m_srcs.size());
   for(const auto& src : m_srcs) {
      sources.push_back(src->name());
   }
   return sources;
}

size_t Entropy_Sources::poll(RandomNumberGenerator& rng, size_t poll_bits, std::chrono::milliseconds timeout) {
   typedef std::chrono::system_clock clock;

   auto deadline = clock::now() + timeout;

   size_t bits_collected = 0;

   for(auto& src : m_srcs) {
      bits_collected += src->poll(rng);

      if(bits_collected >= poll_bits || clock::now() > deadline) {
         break;
      }
   }

   return bits_collected;
}

size_t Entropy_Sources::poll_just(RandomNumberGenerator& rng, std::string_view the_src) {
   for(auto& src : m_srcs) {
      if(src->name() == the_src) {
         return src->poll(rng);
      }
   }

   return 0;
}

Entropy_Sources::Entropy_Sources(const std::vector<std::string>& sources) {
   for(auto&& src_name : sources) {
      add_source(Entropy_Source::create(src_name));
   }
}

Entropy_Sources& Entropy_Sources::global_sources() {
   static Entropy_Sources global_entropy_sources(BOTAN_ENTROPY_DEFAULT_SOURCES);

   return global_entropy_sources;
}

}  // namespace Botan
/*
* Hex Encoding and Decoding
* (C) 2010,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

namespace {

char hex_encode_nibble(uint8_t n, bool uppercase) {
   BOTAN_DEBUG_ASSERT(n <= 15);

   const auto in_09 = CT::Mask<uint8_t>::is_lt(n, 10);

   const char c_09 = n + '0';
   const char c_af = n + (uppercase ? 'A' : 'a') - 10;

   return in_09.select(c_09, c_af);
}

}  // namespace

void hex_encode(char output[], const uint8_t input[], size_t input_length, bool uppercase) {
   for(size_t i = 0; i != input_length; ++i) {
      const uint8_t n0 = (input[i] >> 4) & 0xF;
      const uint8_t n1 = (input[i]) & 0xF;

      output[2 * i] = hex_encode_nibble(n0, uppercase);
      output[2 * i + 1] = hex_encode_nibble(n1, uppercase);
   }
}

std::string hex_encode(const uint8_t input[], size_t input_length, bool uppercase) {
   std::string output(2 * input_length, 0);

   if(input_length) {
      hex_encode(&output.front(), input, input_length, uppercase);
   }

   return output;
}

namespace {

uint8_t hex_char_to_bin(char input) {
   const uint8_t c = static_cast<uint8_t>(input);

   const auto is_alpha_upper = CT::Mask<uint8_t>::is_within_range(c, uint8_t('A'), uint8_t('F'));
   const auto is_alpha_lower = CT::Mask<uint8_t>::is_within_range(c, uint8_t('a'), uint8_t('f'));
   const auto is_decimal = CT::Mask<uint8_t>::is_within_range(c, uint8_t('0'), uint8_t('9'));

   const auto is_whitespace =
      CT::Mask<uint8_t>::is_any_of(c, {uint8_t(' '), uint8_t('\t'), uint8_t('\n'), uint8_t('\r')});

   const uint8_t c_upper = c - uint8_t('A') + 10;
   const uint8_t c_lower = c - uint8_t('a') + 10;
   const uint8_t c_decim = c - uint8_t('0');

   uint8_t ret = 0xFF;  // default value

   ret = is_alpha_upper.select(c_upper, ret);
   ret = is_alpha_lower.select(c_lower, ret);
   ret = is_decimal.select(c_decim, ret);
   ret = is_whitespace.select(0x80, ret);

   return ret;
}

}  // namespace

size_t hex_decode(uint8_t output[], const char input[], size_t input_length, size_t& input_consumed, bool ignore_ws) {
   uint8_t* out_ptr = output;
   bool top_nibble = true;

   clear_mem(output, input_length / 2);

   for(size_t i = 0; i != input_length; ++i) {
      const uint8_t bin = hex_char_to_bin(input[i]);

      if(bin >= 0x10) {
         if(bin == 0x80 && ignore_ws) {
            continue;
         }

         throw Invalid_Argument(fmt("hex_decode: invalid character '{}'", format_char_for_display(input[i])));
      }

      if(top_nibble) {
         *out_ptr |= bin << 4;
      } else {
         *out_ptr |= bin;
      }

      top_nibble = !top_nibble;
      if(top_nibble) {
         ++out_ptr;
      }
   }

   input_consumed = input_length;
   size_t written = (out_ptr - output);

   /*
   * We only got half of a uint8_t at the end; zap the half-written
   * output and mark it as unread
   */
   if(!top_nibble) {
      *out_ptr = 0;
      input_consumed -= 1;
   }

   return written;
}

size_t hex_decode(uint8_t output[], const char input[], size_t input_length, bool ignore_ws) {
   size_t consumed = 0;
   size_t written = hex_decode(output, input, input_length, consumed, ignore_ws);

   if(consumed != input_length) {
      throw Invalid_Argument("hex_decode: input did not have full bytes");
   }

   return written;
}

size_t hex_decode(uint8_t output[], std::string_view input, bool ignore_ws) {
   return hex_decode(output, input.data(), input.length(), ignore_ws);
}

size_t hex_decode(std::span<uint8_t> output, std::string_view input, bool ignore_ws) {
   return hex_decode(output.data(), input.data(), input.length(), ignore_ws);
}

secure_vector<uint8_t> hex_decode_locked(const char input[], size_t input_length, bool ignore_ws) {
   secure_vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(), input, input_length, ignore_ws);

   bin.resize(written);
   return bin;
}

secure_vector<uint8_t> hex_decode_locked(std::string_view input, bool ignore_ws) {
   return hex_decode_locked(input.data(), input.size(), ignore_ws);
}

std::vector<uint8_t> hex_decode(const char input[], size_t input_length, bool ignore_ws) {
   std::vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(), input, input_length, ignore_ws);

   bin.resize(written);
   return bin;
}

std::vector<uint8_t> hex_decode(std::string_view input, bool ignore_ws) {
   return hex_decode(input.data(), input.size(), ignore_ws);
}

}  // namespace Botan
/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#if defined(BOTAN_HAS_SYSTEM_RNG)
#endif

#include <array>

namespace Botan {

void RandomNumberGenerator::randomize_with_ts_input(std::span<uint8_t> output) {
   if(this->accepts_input()) {
      constexpr auto s_hd_clk = sizeof(decltype(OS::get_high_resolution_clock()));
      constexpr auto s_sys_ts = sizeof(decltype(OS::get_system_timestamp_ns()));
      constexpr auto s_pid = sizeof(decltype(OS::get_process_id()));

      std::array<uint8_t, s_hd_clk + s_sys_ts + s_pid> additional_input = {0};
      auto s_additional_input = std::span(additional_input.begin(), additional_input.end());

      store_le(OS::get_high_resolution_clock(), s_additional_input.data());
      s_additional_input = s_additional_input.subspan(s_hd_clk);

#if defined(BOTAN_HAS_SYSTEM_RNG)
      System_RNG system_rng;
      system_rng.randomize(s_additional_input);
#else
      store_le(OS::get_system_timestamp_ns(), s_additional_input.data());
      s_additional_input = s_additional_input.subspan(s_sys_ts);

      store_le(OS::get_process_id(), s_additional_input.data());
#endif

      this->fill_bytes_with_input(output, additional_input);
   } else {
      this->fill_bytes_with_input(output, {});
   }
}

size_t RandomNumberGenerator::reseed(Entropy_Sources& srcs, size_t poll_bits, std::chrono::milliseconds poll_timeout) {
   if(this->accepts_input()) {
      return srcs.poll(*this, poll_bits, poll_timeout);
   } else {
      return 0;
   }
}

void RandomNumberGenerator::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits) {
   if(this->accepts_input()) {
      this->add_entropy(rng.random_vec(poll_bits / 8));
   }
}

void Null_RNG::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) {
   // throw if caller tries to obtain random bytes
   if(!output.empty()) {
      throw PRNG_Unseeded("Null_RNG called");
   }
}

}  // namespace Botan
/*
* System RNG
* (C) 2014,2015,2017,2018,2022 Jack Lloyd
* (C) 2021 Tom Crowley
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_RTLGENRANDOM)
#elif defined(BOTAN_TARGET_OS_HAS_CRYPTO_NG)
   #include <bcrypt.h>
   #include <windows.h>
#elif defined(BOTAN_TARGET_OS_HAS_CCRANDOM)
   #include <CommonCrypto/CommonRandom.h>
#elif defined(BOTAN_TARGET_OS_HAS_ARC4RANDOM)
   #include <stdlib.h>
#elif defined(BOTAN_TARGET_OS_HAS_GETRANDOM)
   #include <errno.h>
   #include <sys/random.h>
   #include <sys/syscall.h>
   #include <unistd.h>
#elif defined(BOTAN_TARGET_OS_HAS_DEV_RANDOM)
   #include <errno.h>
   #include <fcntl.h>
   #include <unistd.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_RTLGENRANDOM)

class System_RNG_Impl final : public RandomNumberGenerator {
   public:
      System_RNG_Impl() : m_advapi("advapi32.dll") {
         // This throws if the function is not found
         m_rtlgenrandom = m_advapi.resolve<RtlGenRandom_fptr>("SystemFunction036");
      }

      System_RNG_Impl(const System_RNG_Impl& other) = delete;
      System_RNG_Impl(System_RNG_Impl&& other) = delete;
      System_RNG_Impl& operator=(const System_RNG_Impl& other) = delete;
      System_RNG_Impl& operator=(System_RNG_Impl&& other) = delete;

      bool is_seeded() const override { return true; }

      bool accepts_input() const override { return false; }

      void clear() override { /* not possible */
      }

      std::string name() const override { return "RtlGenRandom"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
         const size_t limit = std::numeric_limits<ULONG>::max();

         uint8_t* pData = output.data();
         size_t bytesLeft = output.size();
         while(bytesLeft > 0) {
            const ULONG blockSize = static_cast<ULONG>(std::min(bytesLeft, limit));

            const bool success = m_rtlgenrandom(pData, blockSize) == TRUE;
            if(!success) {
               throw System_Error("RtlGenRandom failed");
            }

            BOTAN_ASSERT(bytesLeft >= blockSize, "Block is oversized");
            bytesLeft -= blockSize;
            pData += blockSize;
         }
      }

   private:
      using RtlGenRandom_fptr = BOOLEAN(NTAPI*)(PVOID, ULONG);

      Dynamically_Loaded_Library m_advapi;
      RtlGenRandom_fptr m_rtlgenrandom;
};

#elif defined(BOTAN_TARGET_OS_HAS_CRYPTO_NG)

class System_RNG_Impl final : public RandomNumberGenerator {
   public:
      System_RNG_Impl() {
         auto ret = ::BCryptOpenAlgorithmProvider(&m_prov, BCRYPT_RNG_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
         if(!BCRYPT_SUCCESS(ret)) {
            throw System_Error("System_RNG failed to acquire crypto provider", ret);
         }
      }

      System_RNG_Impl(const System_RNG_Impl& other) = delete;
      System_RNG_Impl(System_RNG_Impl&& other) = delete;
      System_RNG_Impl& operator=(const System_RNG_Impl& other) = delete;
      System_RNG_Impl& operator=(System_RNG_Impl&& other) = delete;

      ~System_RNG_Impl() override { ::BCryptCloseAlgorithmProvider(m_prov, 0); }

      bool is_seeded() const override { return true; }

      bool accepts_input() const override { return false; }

      void clear() override { /* not possible */
      }

      std::string name() const override { return "crypto_ng"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
         /*
         There is a flag BCRYPT_RNG_USE_ENTROPY_IN_BUFFER to provide
         entropy inputs, but it is ignored in Windows 8 and later.
         */

         const size_t limit = std::numeric_limits<ULONG>::max();

         uint8_t* pData = output.data();
         size_t bytesLeft = output.size();
         while(bytesLeft > 0) {
            const ULONG blockSize = static_cast<ULONG>(std::min(bytesLeft, limit));

            auto ret = BCryptGenRandom(m_prov, static_cast<PUCHAR>(pData), blockSize, 0);
            if(!BCRYPT_SUCCESS(ret)) {
               throw System_Error("System_RNG call to BCryptGenRandom failed", ret);
            }

            BOTAN_ASSERT(bytesLeft >= blockSize, "Block is oversized");
            bytesLeft -= blockSize;
            pData += blockSize;
         }
      }

   private:
      BCRYPT_ALG_HANDLE m_prov;
};

#elif defined(BOTAN_TARGET_OS_HAS_CCRANDOM)

class System_RNG_Impl final : public RandomNumberGenerator {
   public:
      bool accepts_input() const override { return false; }

      bool is_seeded() const override { return true; }

      void clear() override { /* not possible */
      }

      std::string name() const override { return "CCRandomGenerateBytes"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
         if(::CCRandomGenerateBytes(output.data(), output.size()) != kCCSuccess) {
            throw System_Error("System_RNG CCRandomGenerateBytes failed", errno);
         }
      }
};

#elif defined(BOTAN_TARGET_OS_HAS_ARC4RANDOM)

class System_RNG_Impl final : public RandomNumberGenerator {
   public:
      // No constructor or destructor needed as no userland state maintained

      bool accepts_input() const override { return false; }

      bool is_seeded() const override { return true; }

      void clear() override { /* not possible */
      }

      std::string name() const override { return "arc4random"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
         // macOS 10.15 arc4random crashes if called with buf == nullptr && len == 0
         // however it uses ccrng_generate internally which returns a status, ignored
         // to respect arc4random "no-fail" interface contract
         if(!output.empty()) {
            ::arc4random_buf(output.data(), output.size());
         }
      }
};

#elif defined(BOTAN_TARGET_OS_HAS_GETRANDOM)

class System_RNG_Impl final : public RandomNumberGenerator {
   public:
      // No constructor or destructor needed as no userland state maintained

      bool accepts_input() const override { return false; }

      bool is_seeded() const override { return true; }

      void clear() override { /* not possible */
      }

      std::string name() const override { return "getrandom"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
         const unsigned int flags = 0;

         uint8_t* buf = output.data();
         size_t len = output.size();
         while(len > 0) {
   #if defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 25
            const ssize_t got = ::syscall(SYS_getrandom, buf, len, flags);
   #else
            const ssize_t got = ::getrandom(buf, len, flags);
   #endif

            if(got < 0) {
               if(errno == EINTR) {
                  continue;
               }
               throw System_Error("System_RNG getrandom failed", errno);
            }

            buf += got;
            len -= got;
         }
      }
};

#elif defined(BOTAN_TARGET_OS_HAS_DEV_RANDOM)

// Read a random device

class System_RNG_Impl final : public RandomNumberGenerator {
   public:
      System_RNG_Impl() {
   #ifndef O_NOCTTY
      #define O_NOCTTY 0
   #endif

         /*
         * First open /dev/random and read one byte. On old Linux kernels
         * this blocks the RNG until we have been actually seeded.
         */
         m_fd = ::open("/dev/random", O_RDONLY | O_NOCTTY);
         if(m_fd < 0)
            throw System_Error("System_RNG failed to open RNG device", errno);

         uint8_t b;
         const size_t got = ::read(m_fd, &b, 1);
         ::close(m_fd);

         if(got != 1)
            throw System_Error("System_RNG failed to read blocking RNG device");

         m_fd = ::open("/dev/urandom", O_RDWR | O_NOCTTY);

         if(m_fd >= 0) {
            m_writable = true;
         } else {
            /*
            Cannot open in read-write mode. Fall back to read-only,
            calls to add_entropy will fail, but randomize will work
            */
            m_fd = ::open("/dev/urandom", O_RDONLY | O_NOCTTY);
            m_writable = false;
         }

         if(m_fd < 0)
            throw System_Error("System_RNG failed to open RNG device", errno);
      }

      System_RNG_Impl(const System_RNG_Impl& other) = delete;
      System_RNG_Impl(System_RNG_Impl&& other) = delete;
      System_RNG_Impl& operator=(const System_RNG_Impl& other) = delete;
      System_RNG_Impl& operator=(System_RNG_Impl&& other) = delete;

      ~System_RNG_Impl() override {
         ::close(m_fd);
         m_fd = -1;
      }

      bool is_seeded() const override { return true; }

      bool accepts_input() const override { return m_writable; }

      void clear() override { /* not possible */
      }

      std::string name() const override { return "urandom"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override;
      void maybe_write_entropy(std::span<const uint8_t> input);

   private:
      int m_fd;
      bool m_writable;
};

void System_RNG_Impl::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
   maybe_write_entropy(input);

   uint8_t* buf = output.data();
   size_t len = output.size();
   while(len) {
      ssize_t got = ::read(m_fd, buf, len);

      if(got < 0) {
         if(errno == EINTR)
            continue;
         throw System_Error("System_RNG read failed", errno);
      }
      if(got == 0)
         throw System_Error("System_RNG EOF on device");  // ?!?

      buf += got;
      len -= got;
   }
}

void System_RNG_Impl::maybe_write_entropy(std::span<const uint8_t> entropy_input) {
   if(!m_writable || entropy_input.empty())
      return;

   const uint8_t* input = entropy_input.data();
   size_t len = entropy_input.size();
   while(len) {
      ssize_t got = ::write(m_fd, input, len);

      if(got < 0) {
         if(errno == EINTR)
            continue;

         /*
         * This is seen on OS X CI, despite the fact that the man page
         * for macOS urandom explicitly states that writing to it is
         * supported, and write(2) does not document EPERM at all.
         * But in any case EPERM seems indicative of a policy decision
         * by the OS or sysadmin that additional entropy is not wanted
         * in the system pool, so we accept that and return here,
         * since there is no corrective action possible.
         *
         * In Linux EBADF or EPERM is returned if m_fd is not opened for
         * writing.
         */
         if(errno == EPERM || errno == EBADF)
            return;

         // maybe just ignore any failure here and return?
         throw System_Error("System_RNG write failed", errno);
      }

      input += got;
      len -= got;
   }
}

#endif

}  // namespace

RandomNumberGenerator& system_rng() {
   static System_RNG_Impl g_system_rng;
   return g_system_rng;
}

}  // namespace Botan
/*
* (C) 2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <cstdlib>
#include <new>

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
#endif

namespace Botan {

BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size) {
   if(elems == 0 || elem_size == 0) {
      return nullptr;
   }

   // Some calloc implementations do not check for overflow (?!?)

   if(!BOTAN_CHECKED_MUL(elems, elem_size).has_value()) {
      throw std::bad_alloc();
   }

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(void* p = mlock_allocator::instance().allocate(elems, elem_size)) {
      return p;
   }
#endif

#if defined(BOTAN_TARGET_OS_HAS_ALLOC_CONCEAL)
   void* ptr = ::calloc_conceal(elems, elem_size);
#else
   void* ptr = std::calloc(elems, elem_size);  // NOLINT(*-no-malloc)
#endif
   if(!ptr) {
      [[unlikely]] throw std::bad_alloc();
   }
   return ptr;
}

void deallocate_memory(void* p, size_t elems, size_t elem_size) {
   if(p == nullptr) {
      [[unlikely]] return;
   }

   secure_scrub_memory(p, elems * elem_size);

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(mlock_allocator::instance().deallocate(p, elems, elem_size)) {
      return;
   }
#endif

   std::free(p);  // NOLINT(*-no-malloc)
}

void initialize_allocator() {
#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   mlock_allocator::instance();
#endif
}

}  // namespace Botan
/*
* Runtime assertion checking
* (C) 2010,2012,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#if defined(BOTAN_TERMINATE_ON_ASSERTS)
   #include <iostream>
#endif

namespace Botan {

void throw_invalid_argument(const char* message, const char* func, const char* file) {
   throw Invalid_Argument(fmt("{} in {}:{}", message, func, file));
}

void throw_invalid_state(const char* expr, const char* func, const char* file) {
   throw Invalid_State(fmt("Invalid state: expr {} was false in {}:{}", expr, func, file));
}

void assertion_failure(const char* expr_str, const char* assertion_made, const char* func, const char* file, int line) {
   std::ostringstream format;

   format << "False assertion ";

   if(assertion_made && assertion_made[0] != 0) {
      format << "'" << assertion_made << "' (expression " << expr_str << ") ";
   } else {
      format << expr_str << " ";
   }

   if(func) {
      format << "in " << func << " ";
   }

   format << "@" << file << ":" << line;

#if defined(BOTAN_TERMINATE_ON_ASSERTS)
   std::cerr << format.str() << '\n';
   std::abort();
#else
   throw Internal_Error(format.str());
#endif
}

void assert_unreachable(const char* file, int line) {
   const std::string msg = fmt("Codepath that was marked unreachable was reached @{}:{}", file, line);

#if defined(BOTAN_TERMINATE_ON_ASSERTS)
   std::cerr << msg << '\n';
   std::abort();
#else
   throw Internal_Error(msg);
#endif
}

}  // namespace Botan
/*
* Calendar Functions
* (C) 1999-2010,2017 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <ctime>
#include <iomanip>

namespace Botan {

namespace {

std::tm do_gmtime(std::time_t time_val) {
   std::tm tm;

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   ::gmtime_s(&tm, &time_val);  // Windows
#elif defined(BOTAN_TARGET_OS_HAS_POSIX1)
   ::gmtime_r(&time_val, &tm);  // Unix/SUSv2
#else
   std::tm* tm_p = std::gmtime(&time_val);
   if(tm_p == nullptr)
      throw Encoding_Error("time_t_to_tm could not convert");
   tm = *tm_p;
#endif

   return tm;
}

/*
Portable replacement for timegm, _mkgmtime, etc

Algorithm due to Howard Hinnant

See https://howardhinnant.github.io/date_algorithms.html#days_from_civil
for details and explaination. The code is slightly simplified by our assumption
that the date is at least 1970, which is sufficient for our purposes.
*/
size_t days_since_epoch(uint32_t year, uint32_t month, uint32_t day) {
   if(month <= 2) {
      year -= 1;
   }
   const uint32_t era = year / 400;
   const uint32_t yoe = year - era * 400;                                          // [0, 399]
   const uint32_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;  // [0, 365]
   const uint32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                     // [0, 146096]
   return era * 146097 + doe - 719468;
}

}  // namespace

std::chrono::system_clock::time_point calendar_point::to_std_timepoint() const {
   if(year() < 1970) {
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years before 1970");
   }

   // 32 bit time_t ends at January 19, 2038
   // https://msdn.microsoft.com/en-us/library/2093ets1.aspx
   // Throw after 2037 if 32 bit time_t is used

   if constexpr(sizeof(std::time_t) == 4) {
      if(year() > 2037) {
         throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years after 2037 on this system");
      }
   }

   // This upper bound is completely arbitrary
   if(year() >= 2400) {
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years after 2400");
   }

   const uint64_t seconds_64 =
      (days_since_epoch(year(), month(), day()) * 86400) + (hour() * 60 * 60) + (minutes() * 60) + seconds();

   const time_t seconds_time_t = static_cast<time_t>(seconds_64);

   if(seconds_64 - seconds_time_t != 0) {
      throw Invalid_Argument("calendar_point::to_std_timepoint time_t overflow");
   }

   return std::chrono::system_clock::from_time_t(seconds_time_t);
}

std::string calendar_point::to_string() const {
   // desired format: <YYYY>-<MM>-<dd>T<HH>:<mm>:<ss>
   std::stringstream output;
   output << std::setfill('0') << std::setw(4) << year() << "-" << std::setw(2) << month() << "-" << std::setw(2)
          << day() << "T" << std::setw(2) << hour() << ":" << std::setw(2) << minutes() << ":" << std::setw(2)
          << seconds();
   return output.str();
}

calendar_point::calendar_point(const std::chrono::system_clock::time_point& time_point) {
   std::tm tm = do_gmtime(std::chrono::system_clock::to_time_t(time_point));

   m_year = tm.tm_year + 1900;
   m_month = tm.tm_mon + 1;
   m_day = tm.tm_mday;
   m_hour = tm.tm_hour;
   m_minutes = tm.tm_min;
   m_seconds = tm.tm_sec;
}

}  // namespace Botan
/*
* Character Set Handling
* (C) 1999-2007,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

namespace {

void append_utf8_for(std::string& s, uint32_t c) {
   if(c >= 0xD800 && c < 0xE000) {
      throw Decoding_Error("Invalid Unicode character");
   }

   if(c <= 0x7F) {
      const uint8_t b0 = static_cast<uint8_t>(c);
      s.push_back(static_cast<char>(b0));
   } else if(c <= 0x7FF) {
      const uint8_t b0 = 0xC0 | static_cast<uint8_t>(c >> 6);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
   } else if(c <= 0xFFFF) {
      const uint8_t b0 = 0xE0 | static_cast<uint8_t>(c >> 12);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>((c >> 6) & 0x3F);
      const uint8_t b2 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      s.push_back(static_cast<char>(b2));
   } else if(c <= 0x10FFFF) {
      const uint8_t b0 = 0xF0 | static_cast<uint8_t>(c >> 18);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>((c >> 12) & 0x3F);
      const uint8_t b2 = 0x80 | static_cast<uint8_t>((c >> 6) & 0x3F);
      const uint8_t b3 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      s.push_back(static_cast<char>(b2));
      s.push_back(static_cast<char>(b3));
   } else {
      throw Decoding_Error("Invalid Unicode character");
   }
}

}  // namespace

std::string ucs2_to_utf8(const uint8_t ucs2[], size_t len) {
   if(len % 2 != 0) {
      throw Decoding_Error("Invalid length for UCS-2 string");
   }

   const size_t chars = len / 2;

   std::string s;
   for(size_t i = 0; i != chars; ++i) {
      const uint32_t c = load_be<uint16_t>(ucs2, i);
      append_utf8_for(s, c);
   }

   return s;
}

std::string ucs4_to_utf8(const uint8_t ucs4[], size_t len) {
   if(len % 4 != 0) {
      throw Decoding_Error("Invalid length for UCS-4 string");
   }

   const size_t chars = len / 4;

   std::string s;
   for(size_t i = 0; i != chars; ++i) {
      const uint32_t c = load_be<uint32_t>(ucs4, i);
      append_utf8_for(s, c);
   }

   return s;
}

/*
* Convert from ISO 8859-1 to UTF-8
*/
std::string latin1_to_utf8(const uint8_t chars[], size_t len) {
   std::string s;
   for(size_t i = 0; i != len; ++i) {
      const uint32_t c = static_cast<uint8_t>(chars[i]);
      append_utf8_for(s, c);
   }
   return s;
}

std::string format_char_for_display(char c) {
   std::ostringstream oss;

   oss << "'";

   if(c == '\t') {
      oss << "\\t";
   } else if(c == '\n') {
      oss << "\\n";
   } else if(c == '\r') {
      oss << "\\r";
   } else if(static_cast<unsigned char>(c) >= 128) {
      unsigned char z = static_cast<unsigned char>(c);
      oss << "\\x" << std::hex << std::uppercase << static_cast<int>(z);
   } else {
      oss << c;
   }

   oss << "'";

   return oss.str();
}

}  // namespace Botan
/*
* (C) 2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan::CT {

secure_vector<uint8_t> copy_output(CT::Mask<uint8_t> bad_input_u8,
                                   const uint8_t input[],
                                   size_t input_length,
                                   size_t offset) {
   /*
   * We do not poison the input here because if we did we would have
   * to unpoison it at exit. We assume instead that callers have
   * already poisoned the input and will unpoison it at their own
   * time.
   */
   CT::poison(&offset, sizeof(size_t));

   secure_vector<uint8_t> output(input_length);

   auto bad_input = CT::Mask<size_t>::expand(bad_input_u8);

   /*
   * If the offset is greater than input_length then the arguments are
   * invalid. Ideally we would through an exception but that leaks
   * information about the offset. Instead treat it as if the input
   * was invalid.
   */
   bad_input |= CT::Mask<size_t>::is_gt(offset, input_length);

   /*
   * If the input is invalid, then set offset == input_length as a result
   * at the end we will set output_bytes == 0 causing the final result to
   * be an empty vector.
   */
   offset = bad_input.select(input_length, offset);

   /*
   Move the desired output bytes to the front using a slow (O^n)
   but constant time loop that does not leak the value of the offset
   */
   for(size_t i = 0; i != input_length; ++i) {
      /*
      * If bad_input was set then we modified offset to equal the input_length.
      * In that case, this_loop will be greater than input_length, and so is_eq
      * mask will always be false. As a result none of the input values will be
      * written to output.
      *
      * This is ignoring the possibility of integer overflow of offset + i. But
      * for this to happen the input would have to consume nearly the entire
      * address space, and we just allocated an output buffer of equal size.
      */
      const size_t this_loop = offset + i;

      /*
      start index from i rather than 0 since we know j must be >= i + offset
      to have any effect, and starting from i does not reveal information
      */
      for(size_t j = i; j != input_length; ++j) {
         const uint8_t b = input[j];
         const auto is_eq = CT::Mask<size_t>::is_equal(j, this_loop);
         output[i] |= is_eq.if_set_return(b);
      }
   }

   const size_t output_bytes = input_length - offset;

   CT::unpoison(output.data(), output.size());
   CT::unpoison(output_bytes);

   /*
   This is potentially not const time, depending on how std::vector is
   implemented. But since we are always reducing length, it should
   just amount to setting the member var holding the length.
   */
   output.resize(output_bytes);
   return output;
}

secure_vector<uint8_t> strip_leading_zeros(const uint8_t in[], size_t length) {
   size_t leading_zeros = 0;

   auto only_zeros = Mask<uint8_t>::set();

   for(size_t i = 0; i != length; ++i) {
      only_zeros &= CT::Mask<uint8_t>::is_zero(in[i]);
      leading_zeros += only_zeros.if_set_return(1);
   }

   return copy_output(CT::Mask<uint8_t>::cleared(), in, length, leading_zeros);
}

}  // namespace Botan::CT
/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*     2005 Matthew Gregan
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <istream>

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
   #include <fstream>
#endif

namespace Botan {

/*
* Read a single byte from the DataSource
*/
size_t DataSource::read_byte(uint8_t& out) {
   return read(&out, 1);
}

/*
* Peek a single byte from the DataSource
*/
size_t DataSource::peek_byte(uint8_t& out) const {
   return peek(&out, 1, 0);
}

/*
* Discard the next N bytes of the data
*/
size_t DataSource::discard_next(size_t n) {
   uint8_t buf[64] = {0};
   size_t discarded = 0;

   while(n) {
      const size_t got = this->read(buf, std::min(n, sizeof(buf)));
      discarded += got;
      n -= got;

      if(got == 0) {
         break;
      }
   }

   return discarded;
}

/*
* Read from a memory buffer
*/
size_t DataSource_Memory::read(uint8_t out[], size_t length) {
   const size_t got = std::min<size_t>(m_source.size() - m_offset, length);
   copy_mem(out, m_source.data() + m_offset, got);
   m_offset += got;
   return got;
}

bool DataSource_Memory::check_available(size_t n) {
   return (n <= (m_source.size() - m_offset));
}

/*
* Peek into a memory buffer
*/
size_t DataSource_Memory::peek(uint8_t out[], size_t length, size_t peek_offset) const {
   const size_t bytes_left = m_source.size() - m_offset;
   if(peek_offset >= bytes_left) {
      return 0;
   }

   const size_t got = std::min(bytes_left - peek_offset, length);
   copy_mem(out, &m_source[m_offset + peek_offset], got);
   return got;
}

/*
* Check if the memory buffer is empty
*/
bool DataSource_Memory::end_of_data() const {
   return (m_offset == m_source.size());
}

/*
* DataSource_Memory Constructor
*/
DataSource_Memory::DataSource_Memory(std::string_view in) :
      m_source(cast_char_ptr_to_uint8(in.data()), cast_char_ptr_to_uint8(in.data()) + in.length()), m_offset(0) {}

/*
* Read from a stream
*/
size_t DataSource_Stream::read(uint8_t out[], size_t length) {
   m_source.read(cast_uint8_ptr_to_char(out), length);
   if(m_source.bad()) {
      throw Stream_IO_Error("DataSource_Stream::read: Source failure");
   }

   const size_t got = static_cast<size_t>(m_source.gcount());
   m_total_read += got;
   return got;
}

bool DataSource_Stream::check_available(size_t n) {
   const std::streampos orig_pos = m_source.tellg();
   m_source.seekg(0, std::ios::end);
   const size_t avail = static_cast<size_t>(m_source.tellg() - orig_pos);
   m_source.seekg(orig_pos);
   return (avail >= n);
}

/*
* Peek into a stream
*/
size_t DataSource_Stream::peek(uint8_t out[], size_t length, size_t offset) const {
   if(end_of_data()) {
      throw Invalid_State("DataSource_Stream: Cannot peek when out of data");
   }

   size_t got = 0;

   if(offset) {
      secure_vector<uint8_t> buf(offset);
      m_source.read(cast_uint8_ptr_to_char(buf.data()), buf.size());
      if(m_source.bad()) {
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      }
      got = static_cast<size_t>(m_source.gcount());
   }

   if(got == offset) {
      m_source.read(cast_uint8_ptr_to_char(out), length);
      if(m_source.bad()) {
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      }
      got = static_cast<size_t>(m_source.gcount());
   }

   if(m_source.eof()) {
      m_source.clear();
   }
   m_source.seekg(m_total_read, std::ios::beg);

   return got;
}

/*
* Check if the stream is empty or in error
*/
bool DataSource_Stream::end_of_data() const {
   return (!m_source.good());
}

/*
* Return a human-readable ID for this stream
*/
std::string DataSource_Stream::id() const {
   return m_identifier;
}

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(std::string_view path, bool use_binary) :
      m_identifier(path),
      m_source_memory(std::make_unique<std::ifstream>(std::string(path), use_binary ? std::ios::binary : std::ios::in)),
      m_source(*m_source_memory),
      m_total_read(0) {
   if(!m_source.good()) {
      throw Stream_IO_Error(fmt("DataSource: Failure opening file '{}'", path));
   }
}

#endif

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(std::istream& in, std::string_view name) :
      m_identifier(name), m_source(in), m_total_read(0) {}

DataSource_Stream::~DataSource_Stream() = default;

}  // namespace Botan
/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

std::string to_string(ErrorType type) {
   switch(type) {
      case ErrorType::Unknown:
         return "Unknown";
      case ErrorType::SystemError:
         return "SystemError";
      case ErrorType::NotImplemented:
         return "NotImplemented";
      case ErrorType::OutOfMemory:
         return "OutOfMemory";
      case ErrorType::InternalError:
         return "InternalError";
      case ErrorType::IoError:
         return "IoError";
      case ErrorType::InvalidObjectState:
         return "InvalidObjectState";
      case ErrorType::KeyNotSet:
         return "KeyNotSet";
      case ErrorType::InvalidArgument:
         return "InvalidArgument";
      case ErrorType::InvalidKeyLength:
         return "InvalidKeyLength";
      case ErrorType::InvalidNonceLength:
         return "InvalidNonceLength";
      case ErrorType::LookupError:
         return "LookupError";
      case ErrorType::EncodingFailure:
         return "EncodingFailure";
      case ErrorType::DecodingFailure:
         return "DecodingFailure";
      case ErrorType::TLSError:
         return "TLSError";
      case ErrorType::HttpError:
         return "HttpError";
      case ErrorType::InvalidTag:
         return "InvalidTag";
      case ErrorType::RoughtimeError:
         return "RoughtimeError";
      case ErrorType::CommonCryptoError:
         return "CommonCryptoError";
      case ErrorType::Pkcs11Error:
         return "Pkcs11Error";
      case ErrorType::TPMError:
         return "TPMError";
      case ErrorType::DatabaseError:
         return "DatabaseError";
      case ErrorType::ZlibError:
         return "ZlibError";
      case ErrorType::Bzip2Error:
         return "Bzip2Error";
      case ErrorType::LzmaError:
         return "LzmaError";
   }

   // No default case in above switch so compiler warns
   return "Unrecognized Botan error";
}

Exception::Exception(std::string_view msg) : m_msg(msg) {}

Exception::Exception(std::string_view msg, const std::exception& e) : m_msg(fmt("{} failed with {}", msg, e.what())) {}

Exception::Exception(const char* prefix, std::string_view msg) : m_msg(fmt("{} {}", prefix, msg)) {}

Invalid_Argument::Invalid_Argument(std::string_view msg) : Exception(msg) {}

Invalid_Argument::Invalid_Argument(std::string_view msg, std::string_view where) :
      Exception(fmt("{} in {}", msg, where)) {}

Invalid_Argument::Invalid_Argument(std::string_view msg, const std::exception& e) : Exception(msg, e) {}

namespace {

std::string format_lookup_error(std::string_view type, std::string_view algo, std::string_view provider) {
   if(provider.empty()) {
      return fmt("Unavailable {} {}", type, algo);
   } else {
      return fmt("Unavailable {} {} for provider {}", type, algo, provider);
   }
}

}  // namespace

Lookup_Error::Lookup_Error(std::string_view type, std::string_view algo, std::string_view provider) :
      Exception(format_lookup_error(type, algo, provider)) {}

Internal_Error::Internal_Error(std::string_view err) : Exception("Internal error:", err) {}

Unknown_PK_Field_Name::Unknown_PK_Field_Name(std::string_view algo_name, std::string_view field_name) :
      Invalid_Argument(fmt("Unknown field '{}' for algorithm {}", field_name, algo_name)) {}

Invalid_Key_Length::Invalid_Key_Length(std::string_view name, size_t length) :
      Invalid_Argument(fmt("{} cannot accept a key of length {}", name, length)) {}

Invalid_IV_Length::Invalid_IV_Length(std::string_view mode, size_t bad_len) :
      Invalid_Argument(fmt("IV length {} is invalid for {}", bad_len, mode)) {}

Key_Not_Set::Key_Not_Set(std::string_view algo) : Invalid_State(fmt("Key not set in {}", algo)) {}

PRNG_Unseeded::PRNG_Unseeded(std::string_view algo) : Invalid_State(fmt("PRNG {} not seeded", algo)) {}

Algorithm_Not_Found::Algorithm_Not_Found(std::string_view name) :
      Lookup_Error(fmt("Could not find any algorithm named '{}'", name)) {}

Provider_Not_Found::Provider_Not_Found(std::string_view algo, std::string_view provider) :
      Lookup_Error(fmt("Could not find provider '{}' for algorithm '{}'", provider, algo)) {}

Invalid_Algorithm_Name::Invalid_Algorithm_Name(std::string_view name) :
      Invalid_Argument(fmt("Invalid algorithm name: '{}'", name)) {}

Encoding_Error::Encoding_Error(std::string_view name) : Exception("Encoding error:", name) {}

Decoding_Error::Decoding_Error(std::string_view name) : Exception(name) {}

Decoding_Error::Decoding_Error(std::string_view category, std::string_view err) :
      Exception(fmt("{}: {}", category, err)) {}

Decoding_Error::Decoding_Error(std::string_view msg, const std::exception& e) : Exception(msg, e) {}

Invalid_Authentication_Tag::Invalid_Authentication_Tag(std::string_view msg) :
      Exception("Invalid authentication tag:", msg) {}

Stream_IO_Error::Stream_IO_Error(std::string_view err) : Exception("I/O error:", err) {}

System_Error::System_Error(std::string_view msg, int err_code) :
      Exception(fmt("{} error code {}", msg, err_code)), m_error_code(err_code) {}

Not_Implemented::Not_Implemented(std::string_view err) : Exception("Not implemented", err) {}

}  // namespace Botan
/*
* (C) 2015,2017,2019 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <deque>
#include <memory>

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <dirent.h>
   #include <functional>
   #include <sys/stat.h>
   #include <sys/types.h>
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)

std::vector<std::string> impl_readdir(std::string_view dir_path) {
   std::vector<std::string> out;
   std::deque<std::string> dir_list;
   dir_list.push_back(std::string(dir_path));

   while(!dir_list.empty()) {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      std::unique_ptr<DIR, std::function<int(DIR*)>> dir(::opendir(cur_path.c_str()), ::closedir);

      if(dir) {
         while(struct dirent* dirent = ::readdir(dir.get())) {
            const std::string filename = dirent->d_name;
            if(filename == "." || filename == "..") {
               continue;
            }

            std::ostringstream full_path_sstr;
            full_path_sstr << cur_path << "/" << filename;
            const std::string full_path = full_path_sstr.str();

            struct stat stat_buf;

            if(::stat(full_path.c_str(), &stat_buf) == -1) {
               continue;
            }

            if(S_ISDIR(stat_buf.st_mode)) {
               dir_list.push_back(full_path);
            } else if(S_ISREG(stat_buf.st_mode)) {
               out.push_back(full_path);
            }
         }
      }
   }

   return out;
}

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)

std::vector<std::string> impl_win32(std::string_view dir_path) {
   std::vector<std::string> out;
   std::deque<std::string> dir_list;
   dir_list.push_back(std::string(dir_path));

   while(!dir_list.empty()) {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      WIN32_FIND_DATAA find_data;
      HANDLE dir = ::FindFirstFileA((cur_path + "/*").c_str(), &find_data);

      if(dir != INVALID_HANDLE_VALUE) {
         do {
            const std::string filename = find_data.cFileName;
            if(filename == "." || filename == "..")
               continue;
            const std::string full_path = cur_path + "/" + filename;

            if(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
               dir_list.push_back(full_path);
            } else {
               out.push_back(full_path);
            }
         } while(::FindNextFileA(dir, &find_data));
      }

      ::FindClose(dir);
   }

   return out;
}
#endif

}  // namespace

bool has_filesystem_impl() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return true;
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   return true;
#else
   return false;
#endif
}

std::vector<std::string> get_files_recursive(std::string_view dir) {
   std::vector<std::string> files;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   files = impl_readdir(dir);
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   files = impl_win32(dir);
#else
   BOTAN_UNUSED(dir);
   throw No_Filesystem_Access();
#endif

   std::sort(files.begin(), files.end());

   return files;
}

}  // namespace Botan
/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

uint8_t ct_compare_u8(const uint8_t x[], const uint8_t y[], size_t len) {
   return CT::is_equal(x, y, len).value();
}

bool constant_time_compare(std::span<const uint8_t> x, std::span<const uint8_t> y) {
   const auto min_size = CT::Mask<size_t>::is_lte(x.size(), y.size()).select(x.size(), y.size());
   const auto equal_size = CT::Mask<size_t>::is_equal(x.size(), y.size());
   const auto equal_content = CT::Mask<size_t>::expand(CT::is_equal(x.data(), y.data(), min_size));
   return (equal_content & equal_size).as_bool();
}

}  // namespace Botan
/*
* OS and machine specific utility functions
* (C) 2015,2016,2017,2018 Jack Lloyd
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#include <chrono>

#if defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
   #include <string.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <errno.h>
   #include <pthread.h>
   #include <setjmp.h>
   #include <signal.h>
   #include <stdlib.h>
   #include <sys/mman.h>
   #include <sys/resource.h>
   #include <sys/types.h>
   #include <termios.h>
   #include <unistd.h>
   #undef B0
#endif

#if defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   #include <emscripten/emscripten.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_IS_ANDROID) || \
   defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   #include <sys/auxv.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_AUXINFO)
   #include <dlfcn.h>
   #include <elf.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
   #if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
      #include <libloaderapi.h>
      #include <stringapiset.h>
   #endif
#endif

#if defined(BOTAN_TARGET_OS_IS_ANDROID)
   #include <elf.h>
extern "C" char** environ;
#endif

#if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
   #include <mach/vm_statistics.h>
   #include <sys/sysctl.h>
   #include <sys/types.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_PRCTL)
   #include <sys/prctl.h>
#endif

#if defined(BOTAN_TARGET_OS_IS_FREEBSD) || defined(BOTAN_TARGET_OS_IS_OPENBSD) || defined(BOTAN_TARGET_OS_IS_DRAGONFLY)
   #include <pthread_np.h>
#endif

#if defined(BOTAN_TARGET_OS_IS_HAIKU)
   #include <kernel/OS.h>
#endif

namespace Botan {

// Not defined in OS namespace for historical reasons
void secure_scrub_memory(void* ptr, size_t n) {
#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
   ::RtlSecureZeroMemory(ptr, n);

#elif defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
   ::explicit_bzero(ptr, n);

#elif defined(BOTAN_TARGET_OS_HAS_EXPLICIT_MEMSET)
   (void)::explicit_memset(ptr, 0, n);

#elif defined(BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO) && (BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO == 1)
   /*
   Call memset through a static volatile pointer, which the compiler
   should not elide. This construct should be safe in conforming
   compilers, but who knows. I did confirm that on x86-64 GCC 6.1 and
   Clang 3.8 both create code that saves the memset address in the
   data segment and unconditionally loads and jumps to that address.
   */
   static void* (*const volatile memset_ptr)(void*, int, size_t) = std::memset;
   (memset_ptr)(ptr, 0, n);
#else

   volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);

   for(size_t i = 0; i != n; ++i)
      p[i] = 0;
#endif
}

uint32_t OS::get_process_id() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return ::getpid();
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   return ::GetCurrentProcessId();
#elif defined(BOTAN_TARGET_OS_IS_LLVM) || defined(BOTAN_TARGET_OS_IS_NONE)
   return 0;  // truly no meaningful value
#else
   #error "Missing get_process_id"
#endif
}

unsigned long OS::get_auxval(unsigned long id) {
#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL)
   return ::getauxval(id);
#elif defined(BOTAN_TARGET_OS_IS_ANDROID) && defined(BOTAN_TARGET_ARCH_IS_ARM32)

   if(id == 0)
      return 0;

   char** p = environ;

   while(*p++ != nullptr)
      ;

   Elf32_auxv_t* e = reinterpret_cast<Elf32_auxv_t*>(p);

   while(e != nullptr) {
      if(e->a_type == id)
         return e->a_un.a_val;
      e++;
   }

   return 0;
#elif defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   unsigned long auxinfo = 0;
   ::elf_aux_info(static_cast<int>(id), &auxinfo, sizeof(auxinfo));
   return auxinfo;
#elif defined(BOTAN_TARGET_OS_HAS_AUXINFO)
   for(const AuxInfo* auxinfo = static_cast<AuxInfo*>(::_dlauxinfo()); auxinfo != AT_NULL; ++auxinfo) {
      if(id == auxinfo->a_type)
         return auxinfo->a_v;
   }

   return 0;
#else
   BOTAN_UNUSED(id);
   return 0;
#endif
}

bool OS::running_in_privileged_state() {
#if defined(AT_SECURE)
   return OS::get_auxval(AT_SECURE) != 0;
#elif defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return (::getuid() != ::geteuid()) || (::getgid() != ::getegid());
#else
   return false;
#endif
}

uint64_t OS::get_cpu_cycle_counter() {
   uint64_t rtc = 0;

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   LARGE_INTEGER tv;
   ::QueryPerformanceCounter(&tv);
   rtc = tv.QuadPart;

#elif defined(BOTAN_USE_GCC_INLINE_ASM)

   #if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   if(CPUID::has_rdtsc()) {
      uint32_t rtc_low = 0, rtc_high = 0;
      asm volatile("rdtsc" : "=d"(rtc_high), "=a"(rtc_low));
      rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
   }

   #elif defined(BOTAN_TARGET_ARCH_IS_PPC64)

   for(;;) {
      uint32_t rtc_low = 0, rtc_high = 0, rtc_high2 = 0;
      asm volatile("mftbu %0" : "=r"(rtc_high));
      asm volatile("mftb %0" : "=r"(rtc_low));
      asm volatile("mftbu %0" : "=r"(rtc_high2));

      if(rtc_high == rtc_high2) {
         rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
         break;
      }
   }

   #elif defined(BOTAN_TARGET_ARCH_IS_ALPHA)
   asm volatile("rpcc %0" : "=r"(rtc));

      // OpenBSD does not trap access to the %tick register
   #elif defined(BOTAN_TARGET_ARCH_IS_SPARC64) && !defined(BOTAN_TARGET_OS_IS_OPENBSD)
   asm volatile("rd %%tick, %0" : "=r"(rtc));

   #elif defined(BOTAN_TARGET_ARCH_IS_IA64)
   asm volatile("mov %0=ar.itc" : "=r"(rtc));

   #elif defined(BOTAN_TARGET_ARCH_IS_S390X)
   asm volatile("stck 0(%0)" : : "a"(&rtc) : "memory", "cc");

   #elif defined(BOTAN_TARGET_ARCH_IS_HPPA)
   asm volatile("mfctl 16,%0" : "=r"(rtc));  // 64-bit only?

   #else
      //#warning "OS::get_cpu_cycle_counter not implemented"
   #endif

#endif

   return rtc;
}

size_t OS::get_cpu_available() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)

   #if defined(_SC_NPROCESSORS_ONLN)
   const long cpu_online = ::sysconf(_SC_NPROCESSORS_ONLN);
   if(cpu_online > 0) {
      return static_cast<size_t>(cpu_online);
   }
   #endif

   #if defined(_SC_NPROCESSORS_CONF)
   const long cpu_conf = ::sysconf(_SC_NPROCESSORS_CONF);
   if(cpu_conf > 0) {
      return static_cast<size_t>(cpu_conf);
   }
   #endif

#endif

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   // hardware_concurrency is allowed to return 0 if the value is not
   // well defined or not computable.
   const size_t hw_concur = std::thread::hardware_concurrency();

   if(hw_concur > 0) {
      return hw_concur;
   }
#endif

   return 1;
}

uint64_t OS::get_high_resolution_clock() {
   if(uint64_t cpu_clock = OS::get_cpu_cycle_counter()) {
      return cpu_clock;
   }

#if defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   return emscripten_get_now();
#endif

   /*
   If we got here either we either don't have an asm instruction
   above, or (for x86) RDTSC is not available at runtime. Try some
   clock_gettimes and return the first one that works, or otherwise
   fall back to std::chrono.
   */

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)

   // The ordering here is somewhat arbitrary...
   const clockid_t clock_types[] = {
   #if defined(CLOCK_MONOTONIC_HR)
      CLOCK_MONOTONIC_HR,
   #endif
   #if defined(CLOCK_MONOTONIC_RAW)
      CLOCK_MONOTONIC_RAW,
   #endif
   #if defined(CLOCK_MONOTONIC)
      CLOCK_MONOTONIC,
   #endif
   #if defined(CLOCK_PROCESS_CPUTIME_ID)
      CLOCK_PROCESS_CPUTIME_ID,
   #endif
   #if defined(CLOCK_THREAD_CPUTIME_ID)
      CLOCK_THREAD_CPUTIME_ID,
   #endif
   };

   for(clockid_t clock : clock_types) {
      struct timespec ts;
      if(::clock_gettime(clock, &ts) == 0) {
         return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
      }
   }
#endif

   // Plain C++11 fallback
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

uint64_t OS::get_system_timestamp_ns() {
#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)
   struct timespec ts;
   if(::clock_gettime(CLOCK_REALTIME, &ts) == 0) {
      return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
   }
#endif

   auto now = std::chrono::system_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

size_t OS::system_page_size() {
   const size_t default_page_size = 4096;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   long p = ::sysconf(_SC_PAGESIZE);
   if(p > 1) {
      return static_cast<size_t>(p);
   } else {
      return default_page_size;
   }
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   BOTAN_UNUSED(default_page_size);
   SYSTEM_INFO sys_info;
   ::GetSystemInfo(&sys_info);
   return sys_info.dwPageSize;
#else
   return default_page_size;
#endif
}

size_t OS::get_memory_locking_limit() {
   /*
   * Linux defaults to only 64 KiB of mlockable memory per process (too small)
   * but BSDs offer a small fraction of total RAM (more than we need). Bound the
   * total mlock size to 512 KiB which is enough to run the entire test suite
   * without spilling to non-mlock memory (and thus presumably also enough for
   * many useful programs), but small enough that we should not cause problems
   * even if many processes are mlocking on the same machine.
   */
   const size_t max_locked_kb = 512;

   /*
   * If RLIMIT_MEMLOCK is not defined, likely the OS does not support
   * unprivileged mlock calls.
   */
#if defined(RLIMIT_MEMLOCK) && defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   const size_t mlock_requested =
      std::min<size_t>(read_env_variable_sz("BOTAN_MLOCK_POOL_SIZE", max_locked_kb), max_locked_kb);

   if(mlock_requested > 0) {
      struct ::rlimit limits;

      ::getrlimit(RLIMIT_MEMLOCK, &limits);

      if(limits.rlim_cur < limits.rlim_max) {
         limits.rlim_cur = limits.rlim_max;
         ::setrlimit(RLIMIT_MEMLOCK, &limits);
         ::getrlimit(RLIMIT_MEMLOCK, &limits);
      }

      return std::min<size_t>(limits.rlim_cur, mlock_requested * 1024);
   }

#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   const size_t mlock_requested =
      std::min<size_t>(read_env_variable_sz("BOTAN_MLOCK_POOL_SIZE", max_locked_kb), max_locked_kb);

   SIZE_T working_min = 0, working_max = 0;
   if(!::GetProcessWorkingSetSize(::GetCurrentProcess(), &working_min, &working_max)) {
      return 0;
   }

   // According to Microsoft MSDN:
   // The maximum number of pages that a process can lock is equal to the number of pages in its minimum working set minus a small overhead
   // In the book "Windows Internals Part 2": the maximum lockable pages are minimum working set size - 8 pages
   // But the information in the book seems to be inaccurate/outdated
   // I've tested this on Windows 8.1 x64, Windows 10 x64 and Windows 7 x86
   // On all three OS the value is 11 instead of 8
   const size_t overhead = OS::system_page_size() * 11;
   if(working_min > overhead) {
      const size_t lockable_bytes = working_min - overhead;
      return std::min<size_t>(lockable_bytes, mlock_requested * 1024);
   }
#else
   // Not supported on this platform
   BOTAN_UNUSED(max_locked_kb);
#endif

   return 0;
}

bool OS::read_env_variable(std::string& value_out, std::string_view name_view) {
   value_out = "";

   if(running_in_privileged_state()) {
      return false;
   }

#if defined(BOTAN_TARGET_OS_HAS_WIN32) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   const std::string name(name_view);
   char val[128] = {0};
   size_t req_size = 0;
   if(getenv_s(&req_size, val, sizeof(val), name.c_str()) == 0) {
      // Microsoft's implementation always writes a terminating \0,
      // and includes it in the reported length of the environment variable
      // if a value exists.
      if(req_size > 0 && val[req_size - 1] == '\0') {
         value_out = std::string(val);
      } else {
         value_out = std::string(val, req_size);
      }
      return true;
   }
#else
   const std::string name(name_view);
   if(const char* val = std::getenv(name.c_str())) {
      value_out = val;
      return true;
   }
#endif

   return false;
}

size_t OS::read_env_variable_sz(std::string_view name, size_t def) {
   std::string value;
   if(read_env_variable(value, name) && !value.empty()) {
      try {
         const size_t val = std::stoul(value, nullptr);
         return val;
      } catch(std::exception&) { /* ignore it */
      }
   }

   return def;
}

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)

namespace {

int get_locked_fd() {
   #if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
   // On Darwin, tagging anonymous pages allows vmmap to track these.
   // Allowed from 240 to 255 for userland applications
   static constexpr int default_locked_fd = 255;
   int locked_fd = default_locked_fd;

   if(size_t locked_fdl = OS::read_env_variable_sz("BOTAN_LOCKED_FD", default_locked_fd)) {
      if(locked_fdl < 240 || locked_fdl > 255) {
         locked_fdl = default_locked_fd;
      }
      locked_fd = static_cast<int>(locked_fdl);
   }
   return VM_MAKE_TAG(locked_fd);
   #else
   return -1;
   #endif
}

}  // namespace

#endif

std::vector<void*> OS::allocate_locked_pages(size_t count) {
   std::vector<void*> result;

#if(defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)) || \
   defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)

   result.reserve(count);

   const size_t page_size = OS::system_page_size();

   #if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   static const int locked_fd = get_locked_fd();
   #endif

   for(size_t i = 0; i != count; ++i) {
      void* ptr = nullptr;

   #if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)

      int mmap_flags = MAP_PRIVATE;

      #if defined(MAP_ANONYMOUS)
      mmap_flags |= MAP_ANONYMOUS;
      #elif defined(MAP_ANON)
      mmap_flags |= MAP_ANON;
      #endif

      #if defined(MAP_CONCEAL)
      mmap_flags |= MAP_CONCEAL;
      #elif defined(MAP_NOCORE)
      mmap_flags |= MAP_NOCORE;
      #endif

      int mmap_prot = PROT_READ | PROT_WRITE;

      #if defined(PROT_MAX)
      mmap_prot |= PROT_MAX(mmap_prot);
      #endif

      ptr = ::mmap(nullptr,
                   3 * page_size,
                   mmap_prot,
                   mmap_flags,
                   /*fd=*/locked_fd,
                   /*offset=*/0);

      if(ptr == MAP_FAILED) {
         continue;
      }

      // lock the data page
      if(::mlock(static_cast<uint8_t*>(ptr) + page_size, page_size) != 0) {
         ::munmap(ptr, 3 * page_size);
         continue;
      }

      #if defined(MADV_DONTDUMP)
      // we ignore errors here, as DONTDUMP is just a bonus
      ::madvise(static_cast<uint8_t*>(ptr) + page_size, page_size, MADV_DONTDUMP);
      #endif

   #elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
      ptr = ::VirtualAlloc(nullptr, 3 * page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

      if(ptr == nullptr)
         continue;

      if(::VirtualLock(static_cast<uint8_t*>(ptr) + page_size, page_size) == 0) {
         ::VirtualFree(ptr, 0, MEM_RELEASE);
         continue;
      }
   #endif

      std::memset(ptr, 0, 3 * page_size);  // zero data page and both guard pages

      // Attempts to name the data page
      page_named(ptr, 3 * page_size);
      // Make guard page preceeding the data page
      page_prohibit_access(static_cast<uint8_t*>(ptr));
      // Make guard page following the data page
      page_prohibit_access(static_cast<uint8_t*>(ptr) + 2 * page_size);

      result.push_back(static_cast<uint8_t*>(ptr) + page_size);
   }
#else
   BOTAN_UNUSED(count);
#endif

   return result;
}

void OS::page_allow_access(void* page) {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   const size_t page_size = OS::system_page_size();
   ::mprotect(page, page_size, PROT_READ | PROT_WRITE);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   const size_t page_size = OS::system_page_size();
   DWORD old_perms = 0;
   ::VirtualProtect(page, page_size, PAGE_READWRITE, &old_perms);
   BOTAN_UNUSED(old_perms);
#else
   BOTAN_UNUSED(page);
#endif
}

void OS::page_prohibit_access(void* page) {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   const size_t page_size = OS::system_page_size();
   ::mprotect(page, page_size, PROT_NONE);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   const size_t page_size = OS::system_page_size();
   DWORD old_perms = 0;
   ::VirtualProtect(page, page_size, PAGE_NOACCESS, &old_perms);
   BOTAN_UNUSED(old_perms);
#else
   BOTAN_UNUSED(page);
#endif
}

void OS::free_locked_pages(const std::vector<void*>& pages) {
   const size_t page_size = OS::system_page_size();

   for(size_t i = 0; i != pages.size(); ++i) {
      void* ptr = pages[i];

      secure_scrub_memory(ptr, page_size);

      // ptr points to the data page, guard pages are before and after
      page_allow_access(static_cast<uint8_t*>(ptr) - page_size);
      page_allow_access(static_cast<uint8_t*>(ptr) + page_size);

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
      ::munlock(ptr, page_size);
      ::munmap(static_cast<uint8_t*>(ptr) - page_size, 3 * page_size);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
      ::VirtualUnlock(ptr, page_size);
      ::VirtualFree(static_cast<uint8_t*>(ptr) - page_size, 0, MEM_RELEASE);
#endif
   }
}

void OS::page_named(void* page, size_t size) {
#if defined(BOTAN_TARGET_OS_HAS_PRCTL) && defined(PR_SET_VMA) && defined(PR_SET_VMA_ANON_NAME)
   static constexpr char name[] = "Botan mlock pool";
   int r = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<uintptr_t>(page), size, name);
   BOTAN_UNUSED(r);
#else
   BOTAN_UNUSED(page, size);
#endif
}

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
void OS::set_thread_name(std::thread& thread, const std::string& name) {
   #if defined(BOTAN_TARGET_OS_IS_LINUX) || defined(BOTAN_TARGET_OS_IS_FREEBSD) || defined(BOTAN_TARGET_OS_IS_DRAGONFLY)
   static_cast<void>(pthread_setname_np(thread.native_handle(), name.c_str()));
   #elif defined(BOTAN_TARGET_OS_IS_OPENBSD)
   static_cast<void>(pthread_set_name_np(thread.native_handle(), name.c_str()));
   #elif defined(BOTAN_TARGET_OS_IS_NETBSD)
   static_cast<void>(pthread_setname_np(thread.native_handle(), "%s", const_cast<char*>(name.c_str())));
   #elif defined(BOTAN_TARGET_OS_HAS_WIN32) && defined(_LIBCPP_HAS_THREAD_API_PTHREAD)
   static_cast<void>(pthread_setname_np(thread.native_handle(), name.c_str()));
   #elif defined(BOTAN_TARGET_OS_HAS_WIN32) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   typedef HRESULT(WINAPI * std_proc)(HANDLE, PCWSTR);
   HMODULE kern = GetModuleHandleA("KernelBase.dll");
   std_proc set_thread_name = reinterpret_cast<std_proc>(GetProcAddress(kern, "SetThreadDescription"));
   if(set_thread_name) {
      std::wstring w;
      auto sz = MultiByteToWideChar(CP_UTF8, 0, name.data(), -1, nullptr, 0);
      if(sz > 0) {
         w.resize(sz);
         if(MultiByteToWideChar(CP_UTF8, 0, name.data(), -1, &w[0], sz) > 0) {
            (void)set_thread_name(thread.native_handle(), w.c_str());
         }
      }
   }
   #elif defined(BOTAN_TARGET_OS_IF_HAIKU)
   auto thread_id = get_pthread_thread_id(thread.native_handle());
   static_cast<void>(rename_thread(thread_id, name.c_str()));
   #else
   // TODO other possible oses ?
   // macOs does not seem to allow to name threads other than the current one.
   BOTAN_UNUSED(thread, name);
   #endif
}
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && !defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)

namespace {

// NOLINTNEXTLINE(*-avoid-non-const-global-variables)
::sigjmp_buf g_sigill_jmp_buf;

void botan_sigill_handler(int /*unused*/) {
   siglongjmp(g_sigill_jmp_buf, /*non-zero return value*/ 1);
}

}  // namespace

#endif

int OS::run_cpu_instruction_probe(const std::function<int()>& probe_fn) {
   volatile int probe_result = -3;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && !defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   struct sigaction old_sigaction;
   struct sigaction sigaction;

   sigaction.sa_handler = botan_sigill_handler;
   sigemptyset(&sigaction.sa_mask);
   sigaction.sa_flags = 0;

   int rc = ::sigaction(SIGILL, &sigaction, &old_sigaction);

   if(rc != 0) {
      throw System_Error("run_cpu_instruction_probe sigaction failed", errno);
   }

   rc = sigsetjmp(g_sigill_jmp_buf, /*save sigs*/ 1);

   if(rc == 0) {
      // first call to sigsetjmp
      probe_result = probe_fn();
   } else if(rc == 1) {
      // non-local return from siglongjmp in signal handler: return error
      probe_result = -1;
   }

   // Restore old SIGILL handler, if any
   rc = ::sigaction(SIGILL, &old_sigaction, nullptr);
   if(rc != 0) {
      throw System_Error("run_cpu_instruction_probe sigaction restore failed", errno);
   }

#else
   BOTAN_UNUSED(probe_fn);
#endif

   return probe_result;
}

std::unique_ptr<OS::Echo_Suppression> OS::suppress_echo_on_terminal() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   class POSIX_Echo_Suppression : public Echo_Suppression {
      public:
         POSIX_Echo_Suppression() {
            m_stdin_fd = fileno(stdin);
            if(::tcgetattr(m_stdin_fd, &m_old_termios) != 0) {
               throw System_Error("Getting terminal status failed", errno);
            }

            struct termios noecho_flags = m_old_termios;
            noecho_flags.c_lflag &= ~ECHO;
            noecho_flags.c_lflag |= ECHONL;

            if(::tcsetattr(m_stdin_fd, TCSANOW, &noecho_flags) != 0) {
               throw System_Error("Clearing terminal echo bit failed", errno);
            }
         }

         void reenable_echo() override {
            if(m_stdin_fd > 0) {
               if(::tcsetattr(m_stdin_fd, TCSANOW, &m_old_termios) != 0) {
                  throw System_Error("Restoring terminal echo bit failed", errno);
               }
               m_stdin_fd = -1;
            }
         }

         ~POSIX_Echo_Suppression() override {
            try {
               reenable_echo();
            } catch(...) {}
         }

         POSIX_Echo_Suppression(const POSIX_Echo_Suppression& other) = delete;
         POSIX_Echo_Suppression(POSIX_Echo_Suppression&& other) = delete;
         POSIX_Echo_Suppression& operator=(const POSIX_Echo_Suppression& other) = delete;
         POSIX_Echo_Suppression& operator=(POSIX_Echo_Suppression&& other) = delete;

      private:
         int m_stdin_fd;
         struct termios m_old_termios;
   };

   return std::make_unique<POSIX_Echo_Suppression>();

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)

   class Win32_Echo_Suppression : public Echo_Suppression {
      public:
         Win32_Echo_Suppression() {
            m_input_handle = ::GetStdHandle(STD_INPUT_HANDLE);
            if(::GetConsoleMode(m_input_handle, &m_console_state) == 0)
               throw System_Error("Getting console mode failed", ::GetLastError());

            DWORD new_mode = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
            if(::SetConsoleMode(m_input_handle, new_mode) == 0)
               throw System_Error("Setting console mode failed", ::GetLastError());
         }

         void reenable_echo() override {
            if(m_input_handle != INVALID_HANDLE_VALUE) {
               if(::SetConsoleMode(m_input_handle, m_console_state) == 0)
                  throw System_Error("Setting console mode failed", ::GetLastError());
               m_input_handle = INVALID_HANDLE_VALUE;
            }
         }

         ~Win32_Echo_Suppression() override {
            try {
               reenable_echo();
            } catch(...) {}
         }

         Win32_Echo_Suppression(const Win32_Echo_Suppression& other) = delete;
         Win32_Echo_Suppression(Win32_Echo_Suppression&& other) = delete;
         Win32_Echo_Suppression& operator=(const Win32_Echo_Suppression& other) = delete;
         Win32_Echo_Suppression& operator=(Win32_Echo_Suppression&& other) = delete;

      private:
         HANDLE m_input_handle;
         DWORD m_console_state;
   };

   return std::make_unique<Win32_Echo_Suppression>();

#else

   // Not supported on this platform, return null
   return nullptr;
#endif
}

}  // namespace Botan
/*
* Various string utils and parsing functions
* (C) 1999-2007,2013,2014,2015,2018 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <cctype>
#include <limits>

namespace Botan {

uint16_t to_uint16(std::string_view str) {
   const uint32_t x = to_u32bit(str);

   if(x >> 16) {
      throw Invalid_Argument("Integer value exceeds 16 bit range");
   }

   return static_cast<uint16_t>(x);
}

uint32_t to_u32bit(std::string_view str_view) {
   const std::string str(str_view);

   // std::stoul is not strict enough. Ensure that str is digit only [0-9]*
   for(const char chr : str) {
      if(chr < '0' || chr > '9') {
         throw Invalid_Argument("to_u32bit invalid decimal string '" + str + "'");
      }
   }

   const unsigned long int x = std::stoul(str);

   if constexpr(sizeof(unsigned long int) > 4) {
      // x might be uint64
      if(x > std::numeric_limits<uint32_t>::max()) {
         throw Invalid_Argument("Integer value of " + str + " exceeds 32 bit range");
      }
   }

   return static_cast<uint32_t>(x);
}

/*
* Parse a SCAN-style algorithm name
*/
std::vector<std::string> parse_algorithm_name(std::string_view namex) {
   if(namex.find('(') == std::string::npos && namex.find(')') == std::string::npos) {
      return {std::string(namex)};
   }

   std::string name(namex);
   std::string substring;
   std::vector<std::string> elems;
   size_t level = 0;

   elems.push_back(name.substr(0, name.find('(')));
   name = name.substr(name.find('('));

   for(auto i = name.begin(); i != name.end(); ++i) {
      char c = *i;

      if(c == '(') {
         ++level;
      }
      if(c == ')') {
         if(level == 1 && i == name.end() - 1) {
            if(elems.size() == 1) {
               elems.push_back(substring.substr(1));
            } else {
               elems.push_back(substring);
            }
            return elems;
         }

         if(level == 0 || (level == 1 && i != name.end() - 1)) {
            throw Invalid_Algorithm_Name(namex);
         }
         --level;
      }

      if(c == ',' && level == 1) {
         if(elems.size() == 1) {
            elems.push_back(substring.substr(1));
         } else {
            elems.push_back(substring);
         }
         substring.clear();
      } else {
         substring += c;
      }
   }

   if(!substring.empty()) {
      throw Invalid_Algorithm_Name(namex);
   }

   return elems;
}

std::vector<std::string> split_on(std::string_view str, char delim) {
   std::vector<std::string> elems;
   if(str.empty()) {
      return elems;
   }

   std::string substr;
   for(auto i = str.begin(); i != str.end(); ++i) {
      if(*i == delim) {
         if(!substr.empty()) {
            elems.push_back(substr);
         }
         substr.clear();
      } else {
         substr += *i;
      }
   }

   if(substr.empty()) {
      throw Invalid_Argument(fmt("Unable to split string '{}", str));
   }
   elems.push_back(substr);

   return elems;
}

/*
* Join a string
*/
std::string string_join(const std::vector<std::string>& strs, char delim) {
   std::ostringstream out;

   for(size_t i = 0; i != strs.size(); ++i) {
      if(i != 0) {
         out << delim;
      }
      out << strs[i];
   }

   return out.str();
}

/*
* Convert a decimal-dotted string to binary IP
*/
uint32_t string_to_ipv4(std::string_view str) {
   const auto parts = split_on(str, '.');

   if(parts.size() != 4) {
      throw Decoding_Error(fmt("Invalid IPv4 string '{}'", str));
   }

   uint32_t ip = 0;

   for(auto part = parts.begin(); part != parts.end(); ++part) {
      uint32_t octet = to_u32bit(*part);

      if(octet > 255) {
         throw Decoding_Error(fmt("Invalid IPv4 string '{}'", str));
      }

      ip = (ip << 8) | (octet & 0xFF);
   }

   return ip;
}

/*
* Convert an IP address to decimal-dotted string
*/
std::string ipv4_to_string(uint32_t ip) {
   std::string str;
   uint8_t bits[4];
   store_be(ip, bits);

   for(size_t i = 0; i != 4; ++i) {
      if(i > 0) {
         str += ".";
      }
      str += std::to_string(bits[i]);
   }

   return str;
}

std::string tolower_string(std::string_view in) {
   std::string s(in);
   for(size_t i = 0; i != s.size(); ++i) {
      const int cu = static_cast<unsigned char>(s[i]);
      if(std::isalpha(cu)) {
         s[i] = static_cast<char>(std::tolower(cu));
      }
   }
   return s;
}

bool host_wildcard_match(std::string_view issued_, std::string_view host_) {
   const std::string issued = tolower_string(issued_);
   const std::string host = tolower_string(host_);

   if(host.empty() || issued.empty()) {
      return false;
   }

   /*
   If there are embedded nulls in your issued name
   Well I feel bad for you son
   */
   if(std::count(issued.begin(), issued.end(), char(0)) > 0) {
      return false;
   }

   // If more than one wildcard, then issued name is invalid
   const size_t stars = std::count(issued.begin(), issued.end(), '*');
   if(stars > 1) {
      return false;
   }

   // '*' is not a valid character in DNS names so should not appear on the host side
   if(std::count(host.begin(), host.end(), '*') != 0) {
      return false;
   }

   // Similarly a DNS name can't end in .
   if(host[host.size() - 1] == '.') {
      return false;
   }

   // And a host can't have an empty name component, so reject that
   if(host.find("..") != std::string::npos) {
      return false;
   }

   // Exact match: accept
   if(issued == host) {
      return true;
   }

   /*
   Otherwise it might be a wildcard

   If the issued size is strictly longer than the hostname size it
   couldn't possibly be a match, even if the issued value is a
   wildcard. The only exception is when the wildcard ends up empty
   (eg www.example.com matches www*.example.com)
   */
   if(issued.size() > host.size() + 1) {
      return false;
   }

   // If no * at all then not a wildcard, and so not a match
   if(stars != 1) {
      return false;
   }

   /*
   Now walk through the issued string, making sure every character
   matches. When we come to the (singular) '*', jump forward in the
   hostname by the corresponding amount. We know exactly how much
   space the wildcard takes because it must be exactly `len(host) -
   len(issued) + 1 chars`.

   We also verify that the '*' comes in the leftmost component, and
   doesn't skip over any '.' in the hostname.
   */
   size_t dots_seen = 0;
   size_t host_idx = 0;

   for(size_t i = 0; i != issued.size(); ++i) {
      dots_seen += (issued[i] == '.');

      if(issued[i] == '*') {
         // Fail: wildcard can only come in leftmost component
         if(dots_seen > 0) {
            return false;
         }

         /*
         Since there is only one * we know the tail of the issued and
         hostname must be an exact match. In this case advance host_idx
         to match.
         */
         const size_t advance = (host.size() - issued.size() + 1);

         if(host_idx + advance > host.size()) {  // shouldn't happen
            return false;
         }

         // Can't be any intervening .s that we would have skipped
         if(std::count(host.begin() + host_idx, host.begin() + host_idx + advance, '.') != 0) {
            return false;
         }

         host_idx += advance;
      } else {
         if(issued[i] != host[host_idx]) {
            return false;
         }

         host_idx += 1;
      }
   }

   // Wildcard issued name must have at least 3 components
   if(dots_seen < 2) {
      return false;
   }

   return true;
}

}  // namespace Botan
/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

uint64_t prefetch_array_raw(size_t bytes, const void* arrayv) noexcept {
#if defined(__cpp_lib_hardware_interference_size)
   const size_t cache_line_size = std::hardware_destructive_interference_size;
#else
   // We arbitrarily use a 64 byte cache line, which is by far the most
   // common size.
   //
   // Runtime detection adds too much overhead to this function.
   const size_t cache_line_size = 64;
#endif

   const uint8_t* array = static_cast<const uint8_t*>(arrayv);

   volatile uint64_t combiner = 1;

   for(size_t idx = 0; idx < bytes; idx += cache_line_size) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_prefetch)
      // we have no way of knowing if the compiler will emit anything here
      __builtin_prefetch(&array[idx]);
#endif

      combiner = combiner | array[idx];
   }

   /*
   * The combiner variable is initialized with 1, and we accumulate using OR, so
   * now combiner must be a value other than zero. This being the case we will
   * always return zero here. Hopefully the compiler will not figure this out.
   */
   return ct_is_zero(combiner);
}

}  // namespace Botan
/*
* Simple config/test file reader
* (C) 2013,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

namespace {

std::string clean_ws(std::string_view s) {
   const char* ws = " \t\n";
   auto start = s.find_first_not_of(ws);
   auto end = s.find_last_not_of(ws);

   if(start == std::string::npos) {
      return "";
   }

   if(end == std::string::npos) {
      return std::string(s.substr(start, end));
   } else {
      return std::string(s.substr(start, start + end + 1));
   }
}

}  // namespace

std::map<std::string, std::string> read_cfg(std::istream& is) {
   std::map<std::string, std::string> kv;
   size_t line = 0;

   while(is.good()) {
      std::string s;

      std::getline(is, s);

      ++line;

      if(s.empty() || s[0] == '#') {
         continue;
      }

      s = clean_ws(s.substr(0, s.find('#')));

      if(s.empty()) {
         continue;
      }

      auto eq = s.find('=');

      if(eq == std::string::npos || eq == 0 || eq == s.size() - 1) {
         throw Decoding_Error("Bad read_cfg input '" + s + "' on line " + std::to_string(line));
      }

      const std::string key = clean_ws(s.substr(0, eq));
      const std::string val = clean_ws(s.substr(eq + 1, std::string::npos));

      kv[key] = val;
   }

   return kv;
}

}  // namespace Botan
/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

std::map<std::string, std::string> read_kv(std::string_view kv) {
   std::map<std::string, std::string> m;
   if(kv.empty()) {
      return m;
   }

   std::vector<std::string> parts;

   try {
      parts = split_on(kv, ',');
   } catch(std::exception&) {
      throw Invalid_Argument("Bad KV spec");
   }

   bool escaped = false;
   bool reading_key = true;
   std::string cur_key;
   std::string cur_val;

   for(char c : kv) {
      if(c == '\\' && !escaped) {
         escaped = true;
      } else if(c == ',' && !escaped) {
         if(cur_key.empty()) {
            throw Invalid_Argument("Bad KV spec empty key");
         }

         if(m.find(cur_key) != m.end()) {
            throw Invalid_Argument("Bad KV spec duplicated key");
         }
         m[cur_key] = cur_val;
         cur_key = "";
         cur_val = "";
         reading_key = true;
      } else if(c == '=' && !escaped) {
         if(reading_key == false) {
            throw Invalid_Argument("Bad KV spec unexpected equals sign");
         }
         reading_key = false;
      } else {
         if(reading_key) {
            cur_key += c;
         } else {
            cur_val += c;
         }

         if(escaped) {
            escaped = false;
         }
      }
   }

   if(!cur_key.empty()) {
      if(reading_key == false) {
         if(m.find(cur_key) != m.end()) {
            throw Invalid_Argument("Bad KV spec duplicated key");
         }
         m[cur_key] = cur_val;
      } else {
         throw Invalid_Argument("Bad KV spec incomplete string");
      }
   }

   return m;
}

}  // namespace Botan
/*
* SCAN Name Abstraction
* (C) 2008-2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

namespace {

std::string make_arg(const std::vector<std::pair<size_t, std::string>>& name, size_t start) {
   std::string output = name[start].second;
   size_t level = name[start].first;

   size_t paren_depth = 0;

   for(size_t i = start + 1; i != name.size(); ++i) {
      if(name[i].first <= name[start].first) {
         break;
      }

      if(name[i].first > level) {
         output += "(" + name[i].second;
         ++paren_depth;
      } else if(name[i].first < level) {
         for(size_t j = name[i].first; j < level; j++) {
            output += ")";
            --paren_depth;
         }
         output += "," + name[i].second;
      } else {
         if(output[output.size() - 1] != '(') {
            output += ",";
         }
         output += name[i].second;
      }

      level = name[i].first;
   }

   for(size_t i = 0; i != paren_depth; ++i) {
      output += ")";
   }

   return output;
}

}  // namespace

SCAN_Name::SCAN_Name(const char* algo_spec) : SCAN_Name(std::string(algo_spec)) {}

SCAN_Name::SCAN_Name(std::string_view algo_spec) : m_orig_algo_spec(algo_spec), m_alg_name(), m_args(), m_mode_info() {
   if(algo_spec.empty()) {
      throw Invalid_Argument("Expected algorithm name, got empty string");
   }

   std::vector<std::pair<size_t, std::string>> name;
   size_t level = 0;
   std::pair<size_t, std::string> accum = std::make_pair(level, "");

   const std::string decoding_error = "Bad SCAN name '" + m_orig_algo_spec + "': ";

   for(char c : algo_spec) {
      if(c == '/' || c == ',' || c == '(' || c == ')') {
         if(c == '(') {
            ++level;
         } else if(c == ')') {
            if(level == 0) {
               throw Decoding_Error(decoding_error + "Mismatched parens");
            }
            --level;
         }

         if(c == '/' && level > 0) {
            accum.second.push_back(c);
         } else {
            if(!accum.second.empty()) {
               name.push_back(accum);
            }
            accum = std::make_pair(level, "");
         }
      } else {
         accum.second.push_back(c);
      }
   }

   if(!accum.second.empty()) {
      name.push_back(accum);
   }

   if(level != 0) {
      throw Decoding_Error(decoding_error + "Missing close paren");
   }

   if(name.empty()) {
      throw Decoding_Error(decoding_error + "Empty name");
   }

   m_alg_name = name[0].second;

   bool in_modes = false;

   for(size_t i = 1; i != name.size(); ++i) {
      if(name[i].first == 0) {
         m_mode_info.push_back(make_arg(name, i));
         in_modes = true;
      } else if(name[i].first == 1 && !in_modes) {
         m_args.push_back(make_arg(name, i));
      }
   }
}

std::string SCAN_Name::arg(size_t i) const {
   if(i >= arg_count()) {
      throw Invalid_Argument("SCAN_Name::arg " + std::to_string(i) + " out of range for '" + to_string() + "'");
   }
   return m_args[i];
}

std::string SCAN_Name::arg(size_t i, std::string_view def_value) const {
   if(i >= arg_count()) {
      return std::string(def_value);
   }
   return m_args[i];
}

size_t SCAN_Name::arg_as_integer(size_t i, size_t def_value) const {
   if(i >= arg_count()) {
      return def_value;
   }
   return to_u32bit(m_args[i]);
}

size_t SCAN_Name::arg_as_integer(size_t i) const {
   return to_u32bit(arg(i));
}

}  // namespace Botan
/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

namespace {

std::string format_timer_name(std::string_view name, std::string_view provider) {
   if(provider.empty() || provider == "base") {
      return std::string(name);
   }

   std::ostringstream out;
   out << name << " [" << provider << "]";
   return out.str();
}

}  // namespace

Timer::Timer(std::string_view name,
             std::string_view provider,
             std::string_view doing,
             uint64_t event_mult,
             size_t buf_size,
             double clock_cycle_ratio,
             uint64_t clock_speed) :
      m_name(format_timer_name(name, provider)),
      m_doing(doing),
      m_buf_size(buf_size),
      m_event_mult(event_mult),
      m_clock_cycle_ratio(clock_cycle_ratio),
      m_clock_speed(clock_speed) {}

void Timer::start() {
   stop();
   m_timer_start = OS::get_system_timestamp_ns();
   m_cpu_cycles_start = OS::get_cpu_cycle_counter();
}

void Timer::stop() {
   if(m_timer_start) {
      if(m_cpu_cycles_start != 0) {
         const uint64_t cycles_taken = OS::get_cpu_cycle_counter() - m_cpu_cycles_start;
         if(cycles_taken > 0) {
            m_cpu_cycles_used += static_cast<size_t>(cycles_taken * m_clock_cycle_ratio);
         }
      }

      const uint64_t now = OS::get_system_timestamp_ns();

      if(now > m_timer_start) {
         const uint64_t dur = now - m_timer_start;

         m_time_used += dur;

         if(m_event_count == 0) {
            m_min_time = m_max_time = dur;
         } else {
            m_max_time = std::max(m_max_time, dur);
            m_min_time = std::min(m_min_time, dur);
         }
      }

      m_timer_start = 0;
      ++m_event_count;
   }
}

bool Timer::operator<(const Timer& other) const {
   if(this->doing() != other.doing()) {
      return (this->doing() < other.doing());
   }

   return (this->get_name() < other.get_name());
}

std::string Timer::to_string() const {
   if(!m_custom_msg.empty()) {
      return m_custom_msg;
   } else if(this->buf_size() == 0) {
      return result_string_ops();
   } else {
      return result_string_bps();
   }
}

std::string Timer::result_string_bps() const {
   const size_t MiB = 1024 * 1024;

   const double MiB_total = static_cast<double>(events()) / MiB;
   const double MiB_per_sec = MiB_total / seconds();

   std::ostringstream oss;
   oss << get_name();

   if(!doing().empty()) {
      oss << " " << doing();
   }

   if(buf_size() > 0) {
      oss << " buffer size " << buf_size() << " bytes:";
   }

   if(events() == 0) {
      oss << " "
          << "N/A";
   } else {
      oss << " " << std::fixed << std::setprecision(3) << MiB_per_sec << " MiB/sec";
   }

   if(cycles_consumed() != 0) {
      const double cycles_per_byte = static_cast<double>(cycles_consumed()) / events();
      oss << " " << std::fixed << std::setprecision(2) << cycles_per_byte << " cycles/byte";
   }

   oss << " (" << MiB_total << " MiB in " << milliseconds() << " ms)\n";

   return oss.str();
}

std::string Timer::result_string_ops() const {
   std::ostringstream oss;

   oss << get_name() << " ";

   if(events() == 0) {
      oss << "no events\n";
   } else {
      oss << static_cast<uint64_t>(events_per_second()) << ' ' << doing() << "/sec; " << std::setprecision(2)
          << std::fixed << ms_per_event() << " ms/op";

      if(cycles_consumed() != 0) {
         const double cycles_per_op = static_cast<double>(cycles_consumed()) / events();
         const int precision = (cycles_per_op < 10000) ? 2 : 0;
         oss << " " << std::fixed << std::setprecision(precision) << cycles_per_op << " cycles/op";
      }

      oss << " (" << events() << " " << (events() == 1 ? "op" : "ops") << " in " << milliseconds() << " ms)\n";
   }

   return oss.str();
}

}  // namespace Botan
/*
* Version Information
* (C) 1999-2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



namespace Botan {

/*
  These are intentionally compiled rather than inlined, so an
  application running against a shared library can test the true
  version they are running against.
*/

// NOLINTNEXTLINE(*-macro-usage)
#define QUOTE(name) #name
// NOLINTNEXTLINE(*-macro-usage)
#define STR(macro) QUOTE(macro)

const char* short_version_cstr() {
   return STR(BOTAN_VERSION_MAJOR) "." STR(BOTAN_VERSION_MINOR) "." STR(BOTAN_VERSION_PATCH)
#if defined(BOTAN_VERSION_SUFFIX)
      STR(BOTAN_VERSION_SUFFIX)
#endif
         ;
}

const char* version_cstr() {
   /*
   It is intentional that this string is a compile-time constant;
   it makes it much easier to find in binaries.
   */

   return "Botan " STR(BOTAN_VERSION_MAJOR) "." STR(BOTAN_VERSION_MINOR) "." STR(BOTAN_VERSION_PATCH)
#if defined(BOTAN_VERSION_SUFFIX)
      STR(BOTAN_VERSION_SUFFIX)
#endif
         " ("
#if defined(BOTAN_UNSAFE_FUZZER_MODE) || defined(BOTAN_TERMINATE_ON_ASSERTS)
         "UNSAFE "
   #if defined(BOTAN_UNSAFE_FUZZER_MODE)
         "FUZZER MODE "
   #endif
   #if defined(BOTAN_TERMINATE_ON_ASSERTS)
         "TERMINATE ON ASSERTS "
   #endif
         "BUILD "
#endif
      BOTAN_VERSION_RELEASE_TYPE
#if(BOTAN_VERSION_DATESTAMP != 0)
         ", dated " STR(BOTAN_VERSION_DATESTAMP)
#endif
            ", revision " BOTAN_VERSION_VC_REVISION ", distribution " BOTAN_DISTRIBUTION_INFO ")";
}

#undef STR
#undef QUOTE

/*
* Return the version as a string
*/
std::string version_string() {
   return std::string(version_cstr());
}

std::string short_version_string() {
   return std::string(short_version_cstr());
}

uint32_t version_datestamp() {
   return BOTAN_VERSION_DATESTAMP;
}

/*
* Return parts of the version as integers
*/
uint32_t version_major() {
   return BOTAN_VERSION_MAJOR;
}

uint32_t version_minor() {
   return BOTAN_VERSION_MINOR;
}

uint32_t version_patch() {
   return BOTAN_VERSION_PATCH;
}

std::string runtime_version_check(uint32_t major, uint32_t minor, uint32_t patch) {
   if(major != version_major() || minor != version_minor() || patch != version_patch()) {
      return fmt("Warning: linked version ({}) does not match version built against ({}.{}.{})\n",
                 short_version_cstr(),
                 major,
                 minor,
                 patch);
   }

   return "";
}

}  // namespace Botan
