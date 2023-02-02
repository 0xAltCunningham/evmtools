#pragma once

#include <intx/intx.hpp>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace evmtools {
  namespace calldata_decoder {

    /** Hex string constants for masking and decoding parameters */
    namespace constants {
      constexpr std::string_view MASK_4{"FFFFFFFF"};

      // PUSH20 followed by AND is used to "mask" the 32-byte address into its correct type.
      constexpr std::string_view MASK_20{"ffffffffffffffffffffffffffffffffffffffff"};

      constexpr std::string_view EMPTY_4{"00000000"};

      constexpr std::string_view EMPTY_32{
          "0000000000000000000000000000000000000000000000000000000000000000"};

      constexpr std::string_view MAX_U256{
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

      constexpr std::string_view MAX_U128{
          "00000000000000000000000000000000ffffffffffffffffffffffffffffffff"};
    }  // namespace constants

    /** Possible types for decoded params */
    enum class Types {
      AnyZero,
      AnyMax,
      Uint,
      Int,
      Bytes,
      Bool,
      Uint8,
      Bytes1,
      Bytes20,
      Address,
      Selector,
      String,
      Address0,
      ZeroUint,
      MaxUint128
    };

    struct ParamTypes {
      std::vector<Types> types;

      ParamTypes(std::vector<Types> types);

      ParamTypes(std::initializer_list<Types> types);

      ParamTypes();

      // implement copy and move constructors
      ParamTypes(const ParamTypes& other);
      ParamTypes(ParamTypes&& other);

      // implement copy and move assignment operators
      ParamTypes& operator=(const ParamTypes& other);
      ParamTypes& operator=(ParamTypes&& other);

      // implement destructor
      ~ParamTypes();
    };

    struct Params {
      std::string selector;
      std::vector<std::string> params;
      std::vector<ParamTypes> param_types;

      Params(const std::string_view selector, std::vector<std::string> params);

      // declaration of default constructor, copy constructor, move constructor,
      // copy assignment operator, move assignment operator and destructor
      Params();
      Params(const Params& other);
      Params(Params&& other);
      Params& operator=(const Params& other);
      Params& operator=(Params&& other);
      ~Params();
    };

    struct Calldata {
      // Raw calldata being assesed.
      std::string calldata;
      // Method selector being targeted.
      std::string selector;
      // Param types for our method.
      Params main_details;
      // The params found after selector is sliced out.
      std::vector<std::string> raw_params;
      std::vector<std::string> params;
      // Method calls extending from our method.
      // Includes potential types guessed.
      std::vector<Params> nested_details;

      Calldata(const std::string_view calldata);

      /**
       * @brief Parses the method selector the calldata is being sent to and prepares the raw
       * calldata params to be parsed.
       */
      void parse_selector();

      /**
       * @brief Parses the raw calldata params for each param and for any new method selectors.
       */
      void parse_raw_params();

      /**
       * @brief Gets the potential types for all the calldata params.
       *
       */
      void get_param_types();

      /**
       * @brief Parses the length of data in the `params_64` vector of strings, starting from index
       * `from` and for a length of `len`.
       *
       * @param params_64 Vector of strings representing the data to be parsed.
       * @param from Index of `params_64` vector to start parsing from.
       * @param len Length of data to parse.
       * @return An optional size_t that contains the length of parsed data, or `std::nullopt` if
       * nothing was parsed and no params were recorded.
       */
      std::optional<size_t> parse_len(const std::vector<std::string>& params_64, size_t from,
                                      size_t len);
    };

    /**
     * @brief Converts a calldata string into chunks of a given size.
     *
     * @param calldata The calldata string to be converted.
     * @param chunk_size The size of each chunk.
     * @return A vector of strings containing the chunks.
     */
    std::vector<std::string> split_calldata(const std::string_view calldata, size_t chunk_size);

    /**
     * @brief Adds padding of 4 '0s' to the left of a chunk in a vector of strings (chunks) of the
     * same size.
     *
     * @param chunks The vector of strings in which a chunk will be padded.
     * @param chunk_index The index of the chunk to be padded.
     * @return A vector of strings containing the padded chunk.
     */
    std::vector<std::string> pad_chunk_left(std::vector<std::string> chunks, size_t chunk_index);

    using SelectorAndCalldata = std::tuple<std::string, std::string>;

    /**
     * @brief Parses the selector from the calldata string.
     *
     * @param calldata The calldata string to be parsed.
     * @return A tuple containing the selector (if found) and the calldata string without the
     * selector. If the selector is not found, the selector string will be empty bytes (EMPTY_4) and
     * the calldata string will be the same as the input.
     */
    SelectorAndCalldata try_parse_selector(const std::string_view calldata);

    using ChunksAndCalldata = std::tuple<std::vector<std::string>, std::string>;

    /**
     * @brief Replaces a chunk in a vector of strings (chunks) with a replacement string and moves
     * constants::EMPTY_4 to the end of the vector.
     *
     * @param chunks The vector of strings in which a chunk will be replaced.
     * @param chunk_index The index of the chunk to be replaced.
     * @param replacement The string to replace the chunk.
     * @return A tuple containing the vector of strings with the replaced chunk and the new
     * concatenated calldata string.
     */
    ChunksAndCalldata rearrange_chunks(std::vector<std::string> chunks, size_t chunk_index,
                                       const std::string_view replacement);

    /**
     * @brief Returns the previous chunk in a vector of strings (chunks), if any.
     *
     * @param chunks The vector of strings.
     * @param chunk_index The index of the chunk to get the previous chunk from.
     * @return An optional string containing the previous chunk, if any.
     */
    std::optional<std::string> previous_chunk(std::vector<std::string> chunks, size_t chunk_index);

    /**
     * @brief Returns the next chunk in a vector of strings (chunks), if any.
     *
     * @param chunks The vector of strings.
     * @param chunk_index The index of the chunk to get the next chunk from.
     * @return An optional string containing the next chunk, if any.
     */
    std::optional<std::string> next_chunk(std::vector<std::string> chunks, size_t chunk_index);

    /**
     * @brief Gets all the potential types of a parameter by checking specific patterns.
     *
     * @param param 32-byte string representation of a parameter.
     * @return All the potential types of the parameter.
     */
    ParamTypes get_param_type(const std::string_view param);

    /**
     * @brief Concept for checking if an unsigned integer is a valid bit size for an intx::uint.
     *
     * @tparam N The unsigned integer to be checked.
     */
    template <unsigned N>
    concept BitSize = requires {
                        N % 8 == 0;
                        N <= 512;
                      };

    /**
     * @brief Converts a 32-byte hex string to a intx::uint.
     *
     * @note Ethereum uses the big-endian byte order for integers in calldata, so the bytes must
     * also be ordered as big-endian (most significant byte first/on the left).
     *
     * @tparam N The bit size of the intx::uint to be returned.
     * @param hex_str The 32-byte hex string to be converted.
     * @return The intx::uint representation of the hex string.
     */
    template <unsigned N>
      requires BitSize<N>
    [[nodiscard]] inline intx::uint<N> uint_from_hex_str(const std::string_view hex_str) noexcept {
      std::vector<uint8_t> byte_vec;

      for (unsigned int i = 0; i < hex_str.length(); i += 2) {
        std::string_view byte_str = hex_str.substr(i, 2);
        byte_vec.push_back((uint8_t)strtoul(std::string{byte_str}.data(), nullptr, 16));
      }

      return intx::be::unsafe::load<intx::uint<N>>(byte_vec.data());
    }

    /**
     * @brief Joins a vector of strings into a single string.
     *
     * @param strings The vector of strings to be joined.
     * @return The joined string.
     */
    [[nodiscard]] inline std::string join_strings(std::vector<std::string> strings) noexcept {
      std::string result{""};
      size_t total_size{0};

      for (const auto& str : strings) {
        total_size += str.size();
      }

      result.reserve(total_size);

      for (const auto& str : strings) {
        result += str;
      }

      return result;
    }

    /**
     * @brief Trims leading zeroes from a string.
     *
     * @param str The string to be trimmed.
     * @return The trimmed string.
     */
    [[nodiscard]] inline std::string trim_zeroes(const std::string_view str) noexcept {
      auto trimmed{std::string{str}};

      size_t pos{str.find_first_not_of("0")};

      if (pos != std::string::npos) {
        trimmed.erase(0, pos);
      }

      return trimmed;
    }

    /**
     * @brief Converts Types enum values to strings
     *
     * @param out std::ostream& to write to
     * @param value Types enum value
     * @return std::ostream& to allow chaining
     */
    [[nodiscard]] inline std::ostream& operator<<(std::ostream& out, const Types value) noexcept {
      static std::map<Types, std::string> strings;
      if (strings.size() == 0) {
#define INSERT_ELEMENT(p) strings[p] = #p
        INSERT_ELEMENT(Types::AnyZero);
        INSERT_ELEMENT(Types::AnyMax);
        INSERT_ELEMENT(Types::Uint);
        INSERT_ELEMENT(Types::Int);
        INSERT_ELEMENT(Types::Bytes);
        INSERT_ELEMENT(Types::Bool);
        INSERT_ELEMENT(Types::Uint8);
        INSERT_ELEMENT(Types::Bytes1);
        INSERT_ELEMENT(Types::Bytes20);
        INSERT_ELEMENT(Types::Address);
        INSERT_ELEMENT(Types::Selector);
        INSERT_ELEMENT(Types::String);
        INSERT_ELEMENT(Types::Address0);
        INSERT_ELEMENT(Types::ZeroUint);
        INSERT_ELEMENT(Types::MaxUint128);
#undef INSERT_ELEMENT
      }

      return out << strings[value];
    }

  }  // namespace calldata_decoder

}  // namespace evmtools
