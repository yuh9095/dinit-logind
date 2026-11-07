core_test = executable(
  'test-core',
  'test_core.c',
  include_directories: include_directories('../../src/core'),
  link_with: core_lib,
  install: false,
)

test('core session and user lifecycle', core_test)

process_identity_test = executable(
  'test-process-identity',
  'test_process_identity.c',
  include_directories: include_directories('../../src/core', '../../src/platform/linux'),
  link_with: [core_lib, linux_identity_lib],
  install: false,
)

test('Linux process identity acquisition', process_identity_test)

peer_credentials_test = executable(
  'test-peer-credentials',
  'test_peer_credentials.c',
  include_directories: include_directories('../../src/core', '../../src/platform/linux'),
  link_with: [core_lib, linux_identity_lib, linux_peer_credentials_lib],
  install: false,
)

test('Linux Unix socket peer credentials', peer_credentials_test)
