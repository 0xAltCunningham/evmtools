#include <doctest/doctest.h>
#include <evmtools/calldata_decoder.h>
#include <evmtools/version.h>

#include <iostream>
#include <string>

TEST_CASE("EvmTools version") {
  static_assert(std::string_view(EVMTOOLS_VERSION) == std::string_view("0.1.0"));
  CHECK(std::string(EVMTOOLS_VERSION) == std::string("0.1.0"));
}

TEST_SUITE("calldata_decoder") {
  using namespace evmtools::calldata_decoder;

  TEST_CASE("parse multicall two-step function calldata") {
    std::string calldata_str{
        "0xac9650d800000000000000000000000000000000000000000000000000000000000000200000000000000000"
        "000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000"
        "000000000000000000004000000000000000000000000000000000000000000000000000000000000001e00000"
        "000000000000000000000000000000000000000000000000000000000164883164560000000000000000000000"
        "00c011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f000000000000000000000000c02aaa39b223fe8d0a0e5c4f"
        "27ead9083c756cc20000000000000000000000000000000000000000000000000000000000002710ffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffee530ffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffff1b18000000000000000000000000000000000000000000000000016345785d89fd"
        "6800000000000000000000000000000000000000000000000000007f73eca3063a000000000000000000000000"
        "000000000000000000000000016042b530ddaec600000000000000000000000000000000000000000000000000"
        "007e59f044bada000000000000000000000000f847e9d51989033b691b8be943f8e9e268f99b9e000000000000"
        "000000000000000000000000000000000000000000006377347700000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000412210e8a"
        "00000000000000000000000000000000000000000000000000000000"};

    Calldata calldata{calldata_str};

    std::cout << "Number of parsed nested params: " << calldata.nested_details.size() << std::endl;

    for (auto parsed_param : calldata.nested_details) {
      std::cout << "Method ID: " << parsed_param.selector << std::endl;
    }
  }

  TEST_CASE("parse normal function calldata") {
    std::string calldata_str{
        "0xa9059cbb0000000000000000000000004d278b35b4fa66e7dc694197826abf76240533af0000000000000000"
        "0000000000000000000000000000000005f7aab8c56b0000"};

    Calldata calldata{calldata_str};

    std::cout << "Method Id: " << calldata.selector << std::endl;

    for (size_t i = 0; i < calldata.params.size(); i++) {
      std::cout << "param: " << calldata.params.at(i) << std::endl;

      for (auto param_type : calldata.main_details.param_types.at(i).types) {
        std::cout << "param type: " << param_type << std::endl;
      }
    }
  }
}
