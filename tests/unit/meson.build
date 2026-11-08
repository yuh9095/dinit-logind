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

termination_test = executable(
  'test-termination',
  'test_termination.c',
  include_directories: include_directories('../../src/session'),
  link_with: termination_lib,
  install: false,
)
test('asynchronous session termination scheduler', termination_test)

termination_store_test = executable(
  'test-termination-store',
  'test_termination_store.c',
  include_directories: include_directories('../../src/session'),
  link_with: termination_store_lib,
  install: false,
)
test('durable termination intent store validation and recovery records',
     termination_store_test)

termination_cgroup_test = executable(
  'test-termination-cgroup',
  'test_termination_cgroup.c',
  include_directories: include_directories('../../src/core', '../../src/platform/linux', '../../src/session'),
  link_with: [linux_identity_lib, linux_cgroup_v2_lib, termination_lib],
  install: false,
)
test('cgroup.kill adapter errors and termination retry', termination_cgroup_test)

runtime_test = executable(
  'test-runtime',
  'test_runtime.c',
  include_directories: include_directories('../../src/core', '../../src/runtime'),
  link_with: [core_lib, runtime_lib],
  install: false,
)
test('runtime directory and persistent linger', runtime_test)

threads_dep = dependency('threads')
dbus_run_session = find_program('dbus-run-session', required: true)

dbus_integration_test = executable(
  'test-dbus-integration',
  'test_dbus_integration.c',
  include_directories: include_directories('../../src/core', '../../src/dbus'),
  dependencies: [libsystemd_dep, threads_dep],
  link_with: [dbus_test_lib, core_lib, linux_identity_lib, linux_cgroup_v2_lib, termination_lib, termination_store_lib, runtime_lib],
  install: false,
)
test('D-Bus login1 object lifecycle and properties',
     dbus_run_session,
     args: ['--', dbus_integration_test],
     timeout: 180)

cgroup_v2_test = executable(
  'test-cgroup-v2',
  'test_cgroup_v2.c',
  include_directories: include_directories('../../src/core', '../../src/platform/linux'),
  link_with: [core_lib, linux_identity_lib, linux_cgroup_v2_lib],
  install: false,
)
test('Linux cgroup v2 session isolation and fail-closed handling', cgroup_v2_test)
