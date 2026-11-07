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

pam_session_test = executable(
  'test-pam-session',
  'test_pam_session.c',
  include_directories: include_directories('../../src/core', '../../src/platform/linux'),
  link_with: [core_lib, linux_identity_lib, linux_peer_credentials_lib, linux_pam_session_lib],
  install: false,
)

test('PAM session socket lifetime', pam_session_test)

pam_ingress_test = executable(
  'test-pam-ingress',
  'test_pam_ingress.c',
  include_directories: include_directories('../../src/core', '../../src/platform/linux'),
  link_with: [core_lib, linux_identity_lib, linux_peer_credentials_lib, linux_pam_session_lib, linux_pam_ingress_lib],
  install: false,
)

test('PAM ingress protocol and lifecycle', pam_ingress_test)

daemon_config_test = executable(
  'test-daemon-config',
  'test_daemon_config.c',
  include_directories: include_directories('../../src/daemon'),
  link_with: daemon_config_lib,
  install: false,
)

test('daemon configuration ownership and parsing', daemon_config_test)
