#include <evmtools/calldata_decoder.h>

// using namespace evmtools::calldata_decoder;

namespace evmtools {
  namespace calldata_decoder {
    ParamTypes::ParamTypes(std::vector<Types> types) : types(types) {}

    ParamTypes::ParamTypes(std::initializer_list<Types> types) : types(types) {}

    ParamTypes::ParamTypes() = default;

    ParamTypes::ParamTypes(const ParamTypes& other) = default;

    ParamTypes::ParamTypes(ParamTypes&& other) = default;

    ParamTypes& ParamTypes::operator=(const ParamTypes& other) = default;
    ParamTypes& ParamTypes::operator=(ParamTypes&& other) = default;

    ParamTypes::~ParamTypes() = default;

    Params::Params(const std::string_view selector, std::vector<std::string> params)
        : selector(selector), params(params), param_types() {}

    Params::Params() = default;

    Params::Params(const Params& other) = default;

    Params::Params(Params&& other) = default;

    Params& Params::operator=(const Params& other) = default;
    Params& Params::operator=(Params&& other) = default;

    Params::~Params() = default;

    Calldata::Calldata(const std::string_view calldata) : calldata(calldata) {
      this->parse_selector();
      this->parse_raw_params();
      this->get_param_types();
    }

    void Calldata::parse_selector() {
      // Remove the '0x' prefix
      if (this->calldata.contains("0x")) {
        this->calldata.erase(0, 2);
      }

      // If calldata is of even length.
      if (this->calldata.size() % 64 == 0) {
        // Separate the calldata into 32-byte chunks.
        this->raw_params = split_calldata(this->calldata, 64);
        // Get function selector from the calldata as the first 4 bytes from the first chunk.
        this->selector = this->raw_params.at(0).substr(0, 8);
        // Remove the first 4 bytes from the first chunk.
        this->raw_params.at(0).erase(0, 8);
      }
      // If calldata is of odd length.
      else {
        // Separate the calldata into 1-byte chunks.
        auto chunks{split_calldata(this->calldata, 2)};

        // Manually create the 4-byte selector using the first 4 chunks.
        this->selector = chunks.at(0) + chunks.at(1) + chunks.at(2) + chunks.at(3);

        // Remove the first 4 chunks.
        chunks.erase(chunks.begin(), chunks.begin() + 4);

        std::vector<std::string> params{""};
        for (auto chunk : chunks) {
          auto len{params.size() - 1};
          // Check if we have the param.
          if (params.at(len).size() == 64) {
            // Add new param.
            params.push_back("");
            // Make sure we're pushing to new param.
            len++;
          }
          params.at(len).append(chunk);
        }

        this->raw_params = params;
      }
    }

    void Calldata::parse_raw_params() {
      size_t i{0};
      size_t skipping{0};
      std::tuple<std::vector<std::string>, bool> params{
          std::make_tuple(std::vector<std::string>{this->raw_params}, false)};

      // TODO...CREATE OFFSET STRUCT
      // TODO...CREATE PC counter/offset identifier for when we reach it to set length
      // ...
      // - PC of offset (e.g.2nd param)
      // - Offset value (e.g. 0x40)
      // - Length       (e.g. 0x02); Default 0 until we reach the offset
      using Offset = std::tuple<size_t, intx::uint128, size_t>;
      std::vector<Offset> offsets;  // pc of offset + offset

      while (i != this->raw_params.size()) {
        if (skipping != 0) {
          i += skipping;
          skipping = 0;
        }

        auto& params_vec{std::get<0>(params)};
        if (params_vec.at(i) == constants::EMPTY_32) {
          params_vec = pad_chunk_left(params_vec, i);
        }

        auto& raw_param{params_vec.at(i)};
        auto trimmed{trim_zeroes(raw_param)};

        // Check if param has selector in it.
        auto parsed{try_parse_selector(raw_param)};
        auto selector{std::get<0>(parsed)};

        // If selector found.
        if (selector != constants::EMPTY_4 && selector != constants::MASK_4) {
          // Check if last param was a length type.
          // They indicate the start of a dynamic type (string, bytes, or array).
          if (auto last = previous_chunk(params_vec, i)) {
            auto last_trimmed{trim_zeroes(*last)};
            intx::uint128 value{uint_from_hex_str<128>(last_trimmed)};
            // Extract selector + params.
            if (auto skip = this->parse_len(params_vec, i, size_t(value))) {
              auto rearranged{rearrange_chunks(params_vec, i, std::get<1>(parsed))};
              params = std::make_tuple(std::get<0>(rearranged), true);

              // How many chars we skip next loop.
              skipping = *skip;
            }
          }
        }

        // Offsets/lengths never have selectors.
        // Therefore, we check common offset/length sizes.
        else if (trimmed.size() <= 4) {
          // Check if value is for dynamic type.
          intx::uint128 value{uint_from_hex_str<128>(trimmed)};
          // Check if offset by checking if
          // - below safety net length, since they probably wont go that high.
          // - divisible by 32 bytes (0x20).
          if (value < intx::uint128{i * 64 + 1920} && value % 64 == intx::uint128{0}) {
            offsets.push_back(std::make_tuple(i, value / 64, 0));
          }
        }

        i++;
      }

      this->params = std::get<0>(params);
    }

    void Calldata::get_param_types() {
      // If our main method calls other methods:
      if (this->nested_details.size() > 0) {
        for (auto& params : this->nested_details) {
          std::vector<ParamTypes> types;

          for (auto param : params.params) {
            auto param_types{get_param_type(param)};
            types.push_back(param_types);
          }

          params.param_types = types;
        }
      }
    }

    std::optional<size_t> Calldata::parse_len(const std::vector<std::string>& params_64,
                                              size_t from, size_t len) {
      auto params{std::vector<std::string>{params_64.begin() + from, params_64.end()}};
      auto calldata{join_strings(params)};
      auto cut{calldata.substr(0, len * 2)};
      size_t remainder{(len * 2) % 64};

      // If remainder is 8, we know it's a function.
      if (remainder == 8) {
        auto first_cut{cut.substr(0, 8)};
        auto second_cut{cut.substr(8)};
        auto new_params{split_calldata(second_cut, 64)};

        // Record params.
        this->nested_details.push_back(Params{first_cut, new_params});

        // If extracting only function.
        if (len == 4) {
          return std::nullopt;
        }

        return (len - 8) * 2 / 64;
      }

      // TODO..FINISH THIS OFF
      // How to cut out strings????
      // If remainder is 56, probably a string/fn selector.
      // else if (remainder == 56) {
      //     let cut = cut.0.split_at(8);
      //     let _new_params = chunkify(cut.1, 64);
      // }

      return std::nullopt;
    }

    std::vector<std::string> split_calldata(const std::string_view calldata, size_t chunk_size) {
      std::vector<std::string> chunks;
      for (size_t i = 0; i < calldata.size(); i += chunk_size) {
        chunks.push_back(std::string(calldata.substr(i, chunk_size)));
      }
      return chunks;
    }

    std::vector<std::string> pad_chunk_left(std::vector<std::string> chunks, size_t chunk_index) {
      chunks[chunk_index] = std::string{constants::EMPTY_4} + chunks[chunk_index];

      chunks[chunk_index].erase(56);

      return split_calldata(join_strings(chunks), 64);
    }

    SelectorAndCalldata try_parse_selector(const std::string_view calldata) {
      auto chunks{split_calldata(calldata, 8)};

      // Extract and replace the function selector if it exists.
      if (chunks.at(0) != constants::EMPTY_4 && chunks.at(1) == constants::EMPTY_4
          && chunks.at(0) != constants::MASK_4) {
        auto selector{chunks.at(0)};
        chunks.erase(chunks.begin());
        return std::make_tuple(selector, join_strings(chunks));
      }

      return std::make_tuple(std::string{constants::EMPTY_4}, join_strings(chunks));
    }

    ChunksAndCalldata rearrange_chunks(std::vector<std::string> chunks, size_t chunk_index,
                                       const std::string_view replacement) {
      chunks[chunk_index] = replacement;

      std::string calldata{join_strings(chunks)};
      calldata.append(constants::EMPTY_4);

      return std::make_tuple(split_calldata(calldata, 64), calldata);
    }

    std::optional<std::string> previous_chunk(std::vector<std::string> chunks, size_t chunk_index) {
      if (chunk_index == 0) {
        return std::nullopt;
      }

      return chunks.at(chunk_index - 1);
    }

    std::optional<std::string> next_chunk(std::vector<std::string> chunks, size_t chunk_index) {
      if (chunk_index == chunks.size() - 1) {
        return std::nullopt;
      }

      return chunks.at(chunk_index + 1);
    }

    ParamTypes get_param_type(const std::string_view param) {
      if (param == constants::EMPTY_32) {
        return ParamTypes{Types::AnyZero};
      } else if (param == constants::MAX_U128) {
        return ParamTypes{Types::MaxUint128};
      } else if (param == constants::MAX_U256) {
        return ParamTypes{Types::AnyMax};
      }

      // Break the param into 4 byte chunks.
      auto chunks{split_calldata(param, 8)};

      // Selector detection:
      // if: !00000000... && !FFFFFFFF... && ________00000000
      if (chunks.at(0) != constants::EMPTY_4 && chunks.at(0) != constants::MASK_4
          && chunks.at(1) == constants::EMPTY_4) {
        return ParamTypes{Types::Selector, Types::String, Types::Bytes};
      }

      // Check if it's an Int by: if FFFFFFFF
      // Ints replace 0s with 1s in bitwise
      if (chunks.at(0) == constants::MASK_4) {
        return ParamTypes{Types::Int};
      } else {
        return ParamTypes{Types::Int, Types::String, Types::Bytes};
      }

      // Check if we found an address:
      // Todo:
      // - Check for optimised addresses via heuristics
      auto trimmed{trim_zeroes(param)};
      if (trimmed.size() == 40) {
        return ParamTypes{Types::Address, Types::Bytes20, Types::Uint};
      }

      intx::uint256 value{uint_from_hex_str<256>(param)};
      // If value is 0 or 1
      if (value < 1) {
        return ParamTypes{Types::Uint8, Types::Bytes1, Types::Bool};
      }

      // If value is of type uint8
      if (value <= 8) {
        return ParamTypes{Types::Uint8, Types::Bytes1};
      }

      // Eliminated some patterns; now we can conclude it can be one of these types.
      return ParamTypes{Types::Uint, Types::Int, Types::Bytes};
    }

  }  // namespace calldata_decoder
}  // namespace evmtools
