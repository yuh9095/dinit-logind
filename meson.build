project(
  'dinit-logind',
  'c',
  version: '0.1.0',
  meson_version: '>= 1.2.0',
  default_options: ['c_std=c11', 'warning_level=3', 'werror=true'],
)

pam_dep = dependency('pam', required: false)

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
  link_with: [core_lib, linux_peer_credentials_lib],
  install: false,
)

linux_pam_ingress_lib = static_library(
  'dinit-logind-linux-pam-ingress',
  'src/platform/linux/pam_ingress.c',
  include_directories: include_directories('src/core', 'src/platform/linux'),
  link_with: [core_lib, linux_identity_lib, linux_peer_credentials_lib, linux_pam_session_lib],
  install: false,
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

subdir('tests/unit')
