## [Unreleased]

- Minimum ruby version 3.0 -> 3.1
- Remove support for OpenSSL 1.1.1
- Remove support for ruby/openssl 3.0.x
- Refactor how version protocols are implemented to greatly improve sorbet coverage
- `Paseto.rbnacl?` is replaced by `Paseto::HAS_RBNACL`

## [0.1.2]

- Fixed versioning in 0.1.1 changelog
- Removed support for ruby/openssl < 3.0.2

## [0.1.1] - 2023-01-02

- Relax the version constraint on openssl depedency

## [0.1.0] - 2022-12-13

- Initial release of ruby-paseto
- Full support for PASETO tokens
- Full support for PASERK extensions
- Entire library, except for custom FFI bindings, uses typed: strict
