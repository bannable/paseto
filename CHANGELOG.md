## [Unreleased]

- Fix UTF-8 validation on v4.local decryption; invalid byte sequences in the decrypted payload could pass `valid_encoding?` on Ruby 3.4+ due to a stale coderange on the libsodium buffer
- Support OpenSSL 4.x (gem dependency widened to `>= 3.3, < 5`)
- Drop the `base64` dependency; the gem now uses core `Array#pack('m0')` / `String#unpack1('m0')` directly, so it no longer requires the bundled-gem-removed-in-3.4 `base64`

## [0.2.0]

- Minimum ruby version 3.0 -> 3.1
- Remove support for OpenSSL 1.1.1
- Remove support for ruby/openssl 3.0.x
- Refactor how version protocols are implemented to greatly improve sorbet coverage
- `Paseto.rbnacl?` is replaced by `Paseto::HAS_RBNACL`
- Fix decoding of multibyte characters in payloads, #216 thanks to @pelted @levicole
- Increased ruby/openssl dependency to 3.3

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
