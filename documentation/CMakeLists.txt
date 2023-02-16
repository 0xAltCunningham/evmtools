cmake_minimum_required(VERSION 3.14...3.22)

project(EvmToolsDocs)

# ---- Dependencies ----
include(../cmake/CPM.cmake)

CPMAddPackage("gh:marzer/m.css#860c3cbfe755f25aa855e68949e0c8044327bbde")
CPMAddPackage(NAME EvmTools SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

# ---- Doxygen variables ----

# set Doxyfile variables
set(DOXYGEN_PROJECT_NAME EvmTools)
set(DOXYGEN_PROJECT_VERSION ${EvmTools_VERSION})
set(DOXYGEN_PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/doxygen")

configure_file(${CMAKE_CURRENT_LIST_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

configure_file(${CMAKE_CURRENT_LIST_DIR}/conf.py ${CMAKE_CURRENT_BINARY_DIR}/conf.py)

add_custom_target(
  GenerateDocs
  ${CMAKE_COMMAND} -E make_directory "${DOXYGEN_OUTPUT_DIRECTORY}"
  COMMAND "${m.css_SOURCE_DIR}/documentation/doxygen.py" "${CMAKE_CURRENT_BINARY_DIR}/conf.py"
  COMMAND echo "Docs written to: ${DOXYGEN_OUTPUT_DIRECTORY}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
