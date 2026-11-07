project(
  'dinit-logind',
  'c',
  version: '0.1.0',
  meson_version: '>= 1.2.0',
  default_options: ['c_std=c11', 'warning_level=3', 'werror=true'],
)

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

subdir('tests/unit')
