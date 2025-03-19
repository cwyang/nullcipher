# Prerequiste
- Perl5 Test2::V0
  - install with cpanm Test2::V0

# Build
```bash
$ cmake . -B build # or

$ cmake -DCMAKE_PREFIX_PATH={openssl_install_path} . -B build 

$ (cd build; make)
```

# Test
```bash
$ (cd build; make test)
```
