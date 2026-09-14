set(LOCAL_LIBRARY_DIRS
  ${CMAKE_SOURCE_DIR}/.local-deps/usr/local/lib
  ${CMAKE_SOURCE_DIR}/.local-deps/usr/lib/x86_64-linux-gnu
)

find_library(EC_TOOLKIT relic
  PATHS ${CMAKE_SOURCE_DIR}/.local-deps/usr/local/lib
  NO_DEFAULT_PATH
  REQUIRED
)
find_library(PARI pari HINTS ${LOCAL_LIBRARY_DIRS} /usr/local/lib /usr/lib/x86_64-linux-gnu)
find_library(GMP gmp HINTS /usr/local/lib /usr/lib/x86_64-linux-gnu)
find_library(ZMQ zmq HINTS ${LOCAL_LIBRARY_DIRS} /usr/local/lib /usr/lib/x86_64-linux-gnu)
foreach(REQUIRED_LIBRARY PARI GMP ZMQ)
  if(NOT ${REQUIRED_LIBRARY})
    message(FATAL_ERROR "Required library ${REQUIRED_LIBRARY} was not found")
  endif()
endforeach()

find_package(Threads REQUIRED)

include(CheckSymbolExists)
set(CMAKE_REQUIRED_INCLUDES ${LOCAL_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${PARI})
unset(PARI_HAS_QFI CACHE)
check_symbol_exists(qfi "pari/pari.h" PARI_HAS_QFI)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)
if(NOT PARI_HAS_QFI)
  add_compile_definitions(PARI_NEEDS_QFI_COMPAT=1)
endif()

add_compile_options(-include ${CMAKE_SOURCE_DIR}/include/pari_compat.h)
add_executable(bob bob.c util.c)
target_link_libraries(bob ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(tumbler tumbler.c util.c)
target_link_libraries(tumbler ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(preswap_client
  preswap_client_v4.c
  batch_verifier.c
  preswap_common.c
  preswap_joint.c
  transport_auth.c
  util.c
)
target_link_libraries(preswap_client ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ} Threads::Threads)
add_executable(preswap_server
  preswap_server_v4.c
  batch_verifier.c
  preswap_common.c
  preswap_joint.c
  transport_auth.c
  util.c
)
target_link_libraries(preswap_server ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ} Threads::Threads)
add_executable(worker_assignment_test worker_assignment_test.c batch_verifier.c
  preswap_common.c preswap_joint.c transport_auth.c host_handoff.c util.c)
target_link_libraries(worker_assignment_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ} Threads::Threads)
add_executable(preswap_gateway
  preswap_gateway.c
  completion_journal.c
  preswap_common.c
  preswap_joint.c
  transport_auth.c
  util.c
)
target_link_libraries(preswap_gateway ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ} Threads::Threads)
add_executable(preswap_client_allocation_profile
  preswap_client_v4.c
  batch_verifier.c
  preswap_common.c
  preswap_joint.c
  transport_auth.c
  allocation_counter.c
  util_profile.c
)
target_compile_definitions(preswap_client_allocation_profile PRIVATE BENCH_ALLOCATION_PROFILE=1)
target_link_libraries(preswap_client_allocation_profile ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ} Threads::Threads)
add_executable(preswap_server_allocation_profile
  preswap_server_v4.c
  batch_verifier.c
  preswap_common.c
  preswap_joint.c
  transport_auth.c
  allocation_counter.c
  util_profile.c
)
target_compile_definitions(preswap_server_allocation_profile PRIVATE BENCH_ALLOCATION_PROFILE=1)
target_link_libraries(preswap_server_allocation_profile ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ} Threads::Threads)
add_executable(curve_keygen curve_keygen.c)
target_link_libraries(curve_keygen ${ZMQ})
add_executable(batch_verifier_test
  batch_verifier_test.c
  batch_verifier.c
  preswap_common.c
  preswap_joint.c
  util.c
)
target_link_libraries(batch_verifier_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(joint_presign_test
  joint_presign_test.c
  batch_verifier.c
  preswap_common.c
  preswap_joint.c
  util.c
)
target_link_libraries(joint_presign_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(completion_journal_test
  completion_journal_test.c
  completion_journal.c
  preswap_common.c
  util.c
)
target_link_libraries(completion_journal_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
target_link_options(completion_journal_test PRIVATE "-Wl,--wrap=fsync")

foreach(HOST_TARGET preswap_client preswap_server preswap_gateway
    preswap_client_allocation_profile preswap_server_allocation_profile
    batch_verifier_test joint_presign_test)
  target_sources(${HOST_TARGET} PRIVATE host_handoff.c)
endforeach()

add_executable(host_cycle_tool host_cycle_tool.c host_handoff.c host_ledger.c host_schedule.c host_recovery.c host_witness.c
  preswap_common.c preswap_joint.c batch_verifier.c util.c)
target_link_libraries(host_cycle_tool ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})

add_executable(vtd_sharing_test vtd_sharing_test.c vtd_sharing.c util.c)
target_link_libraries(vtd_sharing_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(vtd_puzzle_test vtd_puzzle_test.c vtd_puzzle.c)
target_link_libraries(vtd_puzzle_test ${GMP})
add_executable(vtd_transcript_test vtd_transcript_test.c vtd_transcript.c vtd_puzzle.c vtd_range_prover.c util.c)
target_link_libraries(vtd_transcript_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(vtd_openings_test vtd_openings_test.c vtd_openings.c vtd_sharing.c vtd_puzzle.c
  vtd_verify.c vtd_commit.c vtd_wire.c vtd_recovery.c vtd_transcript.c vtd_range_prover.c util.c)
target_link_libraries(vtd_openings_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(vtd_setup_test vtd_setup_test.c vtd_setup.c vtd_puzzle.c)
target_link_libraries(vtd_setup_test ${GMP})
add_executable(vtd_integration_test vtd_integration_test.c host_refund.c vtd_setup.c vtd_openings.c vtd_wire.c
  vtd_sharing.c vtd_puzzle.c vtd_verify.c vtd_commit.c vtd_recovery.c
  vtd_transcript.c vtd_range_prover.c host_handoff.c preswap_common.c preswap_joint.c batch_verifier.c util.c)
target_link_libraries(vtd_integration_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(vtd_public_solver vtd_public_solver.c vtd_wire.c vtd_openings.c
  vtd_sharing.c vtd_puzzle.c vtd_verify.c vtd_commit.c vtd_recovery.c
  vtd_transcript.c vtd_range_prover.c host_handoff.c preswap_common.c
  preswap_joint.c batch_verifier.c util.c)
target_link_libraries(vtd_public_solver ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(host_witness_test host_witness_test.c host_witness.c util.c)
target_link_libraries(host_witness_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(host_ledger_test host_ledger_test.c host_ledger.c host_schedule.c host_refund.c util.c)
target_link_libraries(host_ledger_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ})
add_executable(host_schedule_test host_schedule_test.c host_schedule.c)

add_executable(host_witness_transport_test host_witness_transport_test.c
  host_witness.c transport_auth.c util.c)
target_link_libraries(host_witness_transport_test ${EC_TOOLKIT} ${PARI} ${GMP} ${ZMQ} pthread)
