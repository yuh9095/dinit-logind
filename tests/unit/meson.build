core_test = executable(
  'test-core',
  'test_core.c',
  include_directories: include_directories('../../src/core'),
  link_with: core_lib,
  install: false,
)

test('core session and user lifecycle', core_test)
