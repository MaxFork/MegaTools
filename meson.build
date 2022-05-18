project('megatools', 'c',
  version: '1.11.0',
  default_options: [
    'c_std=gnu99',
  ],
  meson_version : '>= 0.46.0',
  license: 'GPLv3')

cc = meson.get_compiler('c')
add_global_arguments('-Wno-unused', '-Wno-pointer-sign', language: 'c')

deps = [
  dependency('threads'),
  dependency('gio-2.0', version: '>=2.40.0'),
  dependency('libcurl'),
  dependency('openssl'),
]

#if host_machine.system() == 'windows'
#  deps += [cc.find_library('wsock32')]
#endif

# targets

cdata = configuration_data()
cdata.set_quoted('VERSION', meson.project_version())
cfile = configure_file(configuration: cdata, output: 'config.h')

commands = ['df', 'dl', 'get', 'ls', 'test', 'export', 'mkdir', 'put', 'reg', 'rm', 'copy']

executable('megatools',
  'lib/sjson.gen.c',
  'lib/http.c',
  'lib/mega.c',
  'lib/tools.c',
  'tools/df.c',
  'tools/dl.c',
  'tools/get.c',
  'tools/ls.c',
  'tools/test.c',
  'tools/export.c',
  'tools/mkdir.c',
  'tools/put.c',
  'tools/reg.c',
  'tools/rm.c',
  'tools/copy.c',
  'tools/shell.c',
  dependencies: deps,
  include_directories: include_directories('lib', 'tools', '.'),
  install: true
)

#XXX: contrib/bash-completion/megatools

if get_option('symlinks') or true
  meson.add_install_script('install-symlinks.sh', get_option('bindir'))
endif

# docs

install_data(['README', 'NEWS', 'TODO', 'LICENSE'],
  install_dir: join_paths(get_option('datadir'), 'doc', meson.project_name()),
)

manpages = [
  ['megatools', '1'],
  ['megarc', '5'],
]

foreach cmd: commands
  manpages += [['megatools-' + cmd, '1']]
endforeach

# build docs

asciidoc = find_program('asciidoc', required: false)
db2x_xsltproc = find_program('db2x_xsltproc', required: false)
db2x_manxml = find_program('db2x_manxml', required: false)
enable_manpages = asciidoc.found() and db2x_xsltproc.found() and db2x_manxml.found()

if enable_manpages and get_option('man')

foreach mp: manpages
  mandirn = join_paths(get_option('mandir'), 'man' + mp[1])

  docb = custom_target(mp[0] + '-db',
    command: [asciidoc, '-f', files('docs/asciidoc.conf'), '-o', '@OUTPUT@', '-b', 'docbook', '-d', 'manpage', '@INPUT@'],
    output: [mp[0] + '.xml'],
    input: ['docs/' + mp[0] + '.txt'],
    depend_files: [
      'docs/asciidoc.conf',
      'docs/footer.txt',
      'docs/auth-options.txt',
      'docs/basic-options.txt',
      'docs/download-options.txt',
      'docs/network-options.txt',
      'docs/upload-options.txt',
      'docs/remote-paths.txt',
    ],
  )

  mxml = custom_target(mp[0] + '-mxml',
    command: [db2x_xsltproc, '-s', 'man', '--param', 'xref-on-link=0', '@INPUT@', '-o', '@OUTPUT@'],
    output: [mp[0] + '.mxml'],
    input: [docb],
  )

  manx = custom_target(mp[0] + '-man',
    command: [db2x_manxml, '--to-stdout', '@INPUT@'],
    capture: true,
    output: [mp[0] + '.' + mp[1]],
    input: [mxml],
    install: true,
    install_dir: mandirn,
  )
endforeach

endif