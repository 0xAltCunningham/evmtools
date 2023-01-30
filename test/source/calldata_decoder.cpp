#include <doctest/doctest.h>
#include <evmtools/calldata_decoder.h>
#include <evmtools/version.h>
#include <greeter/greeter.h>

#include <string>

TEST_CASE("EvmTools version") {
  static_assert(std::string_view(EVMTOOLS_VERSION) == std::string_view("0.1.0"));
  CHECK(std::string(EVMTOOLS_VERSION) == std::string("0.1.0"));
}
