project(
  'dinit-logind',
  'c',
  version: '0.1.0',
  meson_version: '>= 1.2.0',
  default_options: ['c_std=c11', 'warning_level=3', 'werror=true'],
)

pam_dep = dependency('pam', required: false)
libsystemd_dep = dependency('libsystemd', required: true)

core_lib = static_library(
  'dinit-logind-core',
  'src/core/core.c',
  include_directories: include_directories('src/core'),
  install: false,
)

linux_identity_lib = static_library(
  'dinit-logind-linux-identity',
  'src/platform/linux/process_identity.c',
  include_directories: include_directories('src/core', 'src/platform/linux'),
  install: false,
)

termination_lib = static_library(
  'dinit-logind-termination',
  'src/session/termination.c',
  include_directories: include_directories('src/session'),
  install: false,
)

termination_store_lib = static_library(
  'dinit-logind-termination-store',
  'src/session/termination_store.c',
  include_directories: include_directories('src/session'),
  install: false,
)

linux_cgroup_v2_lib = static_library(
  'dinit-logind-linux-cgroup-v2',
  'src/platform/linux/cgroup_v2.c',
  include_directories: include_directories('src/core', 'src/platform/linux'),
  link_with: linux_identity_lib,
  install: false,
)

dbus_lib = static_library(
  'dinit-logind-dbus',
  'src/dbus/dbus.c',
  include_directories: include_directories('src/core', 'src/dbus', 'src/platform/linux', 'src/session'),
  dependencies: libsystemd_dep,
  link_with: [core_lib, linux_identity_lib, linux_cgroup_v2_lib, termination_lib, termination_store_lib],
  install: false,
)

# The integration test uses a short Polkit deadline to exercise timeout
# handling without making the normal test suite wait for the production limit.
dbus_test_lib = static_library(
  'dinit-logind-dbus-test',
  'src/dbus/dbus.c',
  c_args: ['-DDL_POLKIT_AUTH_TIMEOUT_USEC=100000'],
  include_directories: include_directories('src/core', 'src/dbus', 'src/platform/linux', 'src/session'),
  dependencies: libsystemd_dep,
  link_with: [core_lib, linux_identity_lib, linux_cgroup_v2_lib, termination_lib],
  install: false,
)

linux_peer_credentials_lib = static_library(
  'dinit-logind-linux-peer-credentials',
  'src/platform/linux/peer_credentials.c',
  include_directories: include_directories('src/core', 'src/platform/linux'),
  link_with: linux_identity_lib,
  install: false,
)

linux_pam_session_lib = static_library(
  'dinit-logind-linux-pam-session',
  'src/platform/linux/pam_session.c',
  include_directories: include_directories('src/core', 'src/platform/linux'),
  link_with: [core_lib, linux_peer_credentials_lib, linux_cgroup_v2_lib],
  install: false,
)

linux_pam_ingress_lib = static_library(
  'dinit-logind-linux-pam-ingress',
  'src/platform/linux/pam_ingress.c',
  include_directories: include_directories('src/core', 'src/platform/linux'),
  link_with: [core_lib, linux_identity_lib, linux_peer_credentials_lib, linux_pam_session_lib],
  install: false,
)

runtime_lib = static_library(
  'dinit-logind-runtime',
  'src/runtime/runtime.c',
  include_directories: include_directories('src/core', 'src/runtime'),
  link_with: core_lib,
  install: false,
)

daemon_config_lib = static_library(
  'dinit-logind-daemon-config',
  'src/daemon/config.c',
  include_directories: include_directories('src/daemon'),
  install: false,
)

daemon_exe = executable(
  'dinit-logind',
  'src/daemon/main.c',
  'src/daemon/runtime_socket.c',
  include_directories: include_directories('src/core', 'src/platform/linux', 'src/daemon', 'src/dbus'),
  dependencies: libsystemd_dep,
  link_with: [core_lib, dbus_lib, runtime_lib, linux_identity_lib, linux_peer_credentials_lib, linux_pam_session_lib, linux_pam_ingress_lib, daemon_config_lib, termination_lib, termination_store_lib],
  install: true,
  install_dir: get_option('sbindir'),
)

if pam_dep.found()
  shared_module(
    'pam_dinit_logind',
    'src/pam/pam_dinit_logind.c',
    include_directories: include_directories('src/platform/linux'),
    dependencies: pam_dep,
    name_prefix: '',
    install: false,
  )
endif

install_data('data/org.freedesktop.login1.policy',
  install_dir: get_option('datadir') / 'polkit-1/actions',
)

subdir('tests/unit')

test('daemon version output', daemon_exe, args: ['--version'])
test('daemon help output', daemon_exe, args: ['--help'])
