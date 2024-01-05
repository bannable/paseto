# Paseto

[![Ruby Style Guide](https://img.shields.io/badge/code_style-community-brightgreen.svg)](https://rubystyle.guide) [![CircleCI](https://dl.circleci.com/status-badge/img/gh/bannable/paseto/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/bannable/paseto/tree/main) [![Maintainability](https://api.codeclimate.com/v1/badges/0bc8fcc6751880b68a9c/maintainability)](https://codeclimate.com/github/bannable/paseto/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/0bc8fcc6751880b68a9c/test_coverage)](https://codeclimate.com/github/bannable/paseto/test_coverage)

This is an implementation of the [PASETO token protocol](https://github.com/paseto-standard/paseto-spec), written in Ruby, which supports versions [v3](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-3-nist-modern) and [v4](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-4-sodium-modern). This library passes all [official test vectors](https://github.com/paseto-standard/test-vectors) for supported versions and purposes.

Additionally, the library uses [Sorbet](https://sorbet.org) to enforce types at runtime.

## Installing

### RbNaCl and libsodium

**Optional for v4.local tokens support**: Handling v4.local tokens requires [`RbNaCl`](https://github.com/RubyCrypto/rbnacl) with `libsodium 1.0.0` or newer.

You can find instructions for obtaining libsodium at [libsodium.org](https://libsodium.org).

If you do not intend to create or parse `v4.local` tokens, feel free to skip this dependency.

### Using Bundler

Add the following to your Gemfile:

```ruby
gem 'ruby-paseto'
# and optionally:
gem 'rbnacl', '~> 7.1.1'
```

Then, run `bundle install` and `require 'paseto'`.

## Supported PASETO versions

`paseto` supports these PASETO versions and purposes:
| purpose | v4 | v3 |
| ---------| ---- | ---- |
| `local` | ✅ | ✅ |
| `public` | ✅ | ✅ |

## Support for PASERK types

|                                                                                                                               | v4  | v3  |
| ----------------------------------------------------------------------------------------------------------------------------- | --- | --- |
| [`lid`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/lid.md)                 | ✅  | ✅  |
| [`sid`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/sid.md)                 | ✅  | ✅  |
| [`pid`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/pid.md)                 | ✅  | ✅  |
| [`local`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/local.md)             | ✅  | ✅  |
| [`secret`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/secret.md)           | ✅  | ✅  |
| [`public`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/public.md)           | ✅  | ✅  |
| [`seal`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/seal.md)               | ✅  | ✅  |
| [`local-wrap`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/local-wrap.md)   | ✅  | ✅  |
| [`secret-wrap`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/secret-wrap.md) | ✅  | ✅  |
| [`local-pw`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/local-pw.md)       | ✅  | ✅  |
| [`secret-pw`](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/types/secret-pw.md)     | ✅  | ✅  |

## Implementation Guideline compliance

- [x] require payload to be UTF-8 encoded
- [x] enforce JSON encoding of payload
  - [x] require topmost object to be an object, map, or associative array
- [x] protect against loading off-curve public keys
- [x] support for [Validators](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md)
- [x] protect against arbitrary/invalid data in [Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md)
- [x] [Key-ID support](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#key-id-support)

## Basic Usage

```ruby
claims = { "foo" => "bar", "baz" => 1, "time" => Time.now }
symmetric = Paseto::V4::Local.generate
asymmetric = Paseto::V4::Public.generate

footer = {'kid' => asymmetric.pid}
signed_token = asymmetric.encode(claims, footer: footer)
# => "v4.public.eyJ..."

result = asymmetric.decode(signed_token)
# => <Paseto::Result claims={"exp"=>"2022-12-...", "iat"=>"2022-12-...",
#     "nbf"=>"2022-12-...", "foo"=>"bar", "baz"=>1, "time"=>"2022-12-..."},
#     footer={"kid"=>"k4.pid.Mu7prut6-zPCIkJ..."}>

result.claims == claims
# => false

result.claims['foo'] == 'bar'
# => true

# To opt out of default claims use `encode!`
# When using encode!, footer must be a string if provided
encrypted_token = symmetric.encode!(claims, footer: JSON.dump(footer))
# => "v4.local.aM0k..."

result = symmetric.decode(encrypted_token)
# => <Paseto::Result claims={"foo"=>"bar", "baz"=>1, "time"=>"2022-12-..."},
#     footer={"kid"=>"k4.pid.h8fe-zLYEss_..."}>

result.claims == claims
# => true
```

The `encode` and `decode` methods always comply with the [PASETO Payload Processing guidelines](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md).

`paseto` uses `multi_json` to handle JSON serialization and deserialization, so you may configure your adapter as you please.

**Symbol keys are always converted to strings.** Serializer configurations or options which cause keys to decode as non-string values, such as `symbolize_keys`, or cause registered claim values to decode as non-strings, are unsupported.

```ruby
encrypter.decode(encrypted_token)
# => {"foo" => "bar", "baz" => {"^t"=>"2022-12-08T20:26:55.213+00:00"}}

# You may pass JSON adapter options to encode and decode
encrypter.decode(encrypted_token, mode: :object)
# => {"foo" => "bar", "baz" => 2022-12-08 20:26:55 15023727/70368744177664 +0000}

# Or setting default options with Oj
Oj.default_options = {mode: :object}
encrypter.decode(encrypted_token)
# => {"foo" => "bar", "baz" => 2022-12-08 20:26:55 15023727/70368744177664 +0000}
```

See [Registered Claims](#registered-claims) for more information on registered claim validation.

### Encryption and Decryption

These operations are performed with `Local` key instances, which are always initialized with a 256-bit raw key.

```ruby
crypt = Paseto::V4::Local.generate
token = crypt.encode({'foo' => 'bar'}) # => "v4.local.DhLZ..." (local PASETO)
token = crypt.encode({'foo' => 'bar'},
  footer: '',
  implicit_assertion: ''
)                                      # same as above
result = crypt.decode(token)           # => <Paseto::Result ...>
result.claims                          # => {'foo' => 'bar'}

# exporting key material
crypt.key    # => The IKM used for this key as raw bytes
crypt.lid    # => "k4.lid.uGj..." (PASERK type lid)
crypt.id     # => same as above
crypt.paserk # => "k4.local.tnVpN4t..." (PASERK Type local)
```

### Message Signing and Verification

These options are performed with `Public` key instances, which may be initialized with a DER- or PEM-encoded public or private key.

```ruby
signer = Paseto::V4::Public.generate
token = signer.encode({'foo' => 'bar'}) # => "v4.public.sKd3..." (public PASETO)
token = signer.encode(
  {'foo' => 'bar'},
  footer: '',
  implicit_assertion: ''
)                                       # same as above
result = signer.decode(token)           # => <Paseto::Result ...>
result.claims                           # => {'foo' => 'bar'}

# or initialize only for verification
verifier = Paseto::V4::Public.new(signer.public_to_pem)
verifier.decode(token)            # => <Paseto::Result ...>
verifier.encode({'foo' => 'bar'}) # => ArgumentError

# exporting key material
signer.public_to_pem  # => PEM
signer.private_to_pem # => PEM if private material available, otherwise ArgumentError
signer.sid            # => "k4.sid.y5x..." (PASERK Type sid)
signer.id             # => same as above
signer.pid            # => "k4.pid.5g4..." (PASERK Type pid)
verifier.pid          # => same as above!
verifier.id           # => same as above
```

## PASETO/PASERK v4, Sodium Modern

[Description](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-4-nist-modern) and [Specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md).

The `rbnacl` gem is required for access to any v4 algorithm.

### Encryption and Decryption

```ruby
crypt = Paseto::V4::Local.generate
# or initialize with a known 256-bit string
ikm = SecureRandom.bytes(32)
crypt = Paseto::V4::Local.new(ikm: ikm)
```

### Message Signing and Verification

```ruby
signer = Paseto::V4::Public.generate # => Paseto::V4::Public
# or initialize from a DER- or PEM-encoded Ed25519 key
pem = File.read('my.pem')
signer = Paseto::V4::Public.new(pem)
```

## PASETO v3, NIST Modern

[Description](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-3-nist-modern) and [Specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md).

The `openssl` gem is required for access to any v3 algorithm.

### Encryption and Decryption

```ruby
crypt = Paseto::V3::Local.generate
# or initialize with a known key
ikm = SecureRandom.bytes(32)
crypt = Paseto::V3::Local.new(ikm: ikm)
```

### Message Signing and Verification

```ruby
signer = Paseto::V3::Public.generate # => Paseto::V3::Public
# or initialize from a PEM- or DER-encoded secp384r1 key
signer = Paseto::V3::Public.new(signer.private_to_pem)
```

# PASERK

## Accessing the PASETO Footer Before Decoding

`Paseto::Token` is used for decoding and accessing the different components of a PASETO, and can be used for retrieving a `kid` or `wpk` footer claim before decoding the full token.

`Token` objects respond to `#inspect` and `to_s` with the PASETO token that they represent.

```ruby
signer = Paseto::V4::Public.generate

claims = { "foo" => "bar", "baz" => 1, "time" => Time.now }
footer = '"foo"'
signed_token = signer.encode(claims, footer: footer)

t = Paseto::Token.parse(signed_token) # => the signed_token value
t.class                               # => Paseto::Token
t.footer                              # => "\"foo\""

# You must decode! a Token with the correct Key before accessing the payload
t.payload                             # => Paseto::ParseError
t.decode!(signer)                     # => {"exp"=> ...}
t.payload                             # => {"exp"=> ...}

# The footer is automatically deserialized to a Hash when appropriate
signed_token = signer.encode(claims, footer: {'kid' => signer.pid})
t = Paseto::Token.parse(signed_token) # => "v4.public.fOQ2s..."

t.footer                              # => {"kid"=>"k4.pid.h5u7u..."}
t.footer['kid'] == signer.pid         # => true
key = MyKeyStore.fetch(footer['kid'])
t.decode!(key)                        # => {"exp"=> ...}
```

## [ID](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/operations/ID.md), PASERK IDs

See [Basic Usage](#basic-usage).

## [Wrap](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/operations/Wrap.md), Symmetric-Key Wrapping

Encrypt a symmetric key with another symmetric key using the PIE wrapping algorithm. Other wrapping algorithms are not supported.

```ruby
wrapping_key = Paseto::V4::Local.generate
local_secret = Paseto::V4::Local.generate

# Encrypt local_secret with wrapping_key using the PIE algorithm
paserk = wrapping_key.wrap(local_secret)  # => "k4.local-wrap.pie.8qQp..."

# Decrypt a secret-wrap or local-wrap PASERK
unwrapped = wrapping_key.unwrap(paserk)   # => #<Paseto::V4::Local ...>
unwrapped == local_secret                 # => true
```

## [PKE](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/operations/PKE.md), Public-Key Encryption

Encrypt a symmetric key with a public key, and decrypt with a private key.

```ruby
wrapping_key = Paseto::V4::Public.generate
local_secret = Paseto::V4::Local.generate

# Seal a Local key with a Public key
paserk = wrapping_key.seal(local_secret)  # => "k4.seal.I1Hn..."

# Unseal a sealed PASERK
unwrapped = wrapping_key.unseal(paserk)   # => #<Paseto::V4::Local ...>
unwrapped == local_secret                 # => true
```

## [PBKD](https://github.com/paseto-standard/paserk/blob/8cc4934687a3c9235387d005fb79eec33f43166d/operations/PBKW.md), Password-Based Key Wrapping

**Note:** This operation is slow.

This operation encrypts any key with a password-derived encryption key.

Different parameters for the derivation may be provided depending on the version of the key being encrypted.

```ruby
secret_key = Paseto::V4::Local.generate # May be either Local or Public

# Equivelant to :sensitive for both values
options = { opslimit: 4, memlimit: 1_073_741_824 }

paserk = secret_key.pbkd(password: 'hunter2', options: options)
# => k4.local-pw.hSmzsCmWhiT...

key = Paseto::Paserk.from_paserk(paserk: paserk, password: 'hunter2')
# => #<Paseto::V4::Local ...>

key == secret_key
# => true
```

### Version 4, Argon2id Parameters

|   param    |  allowed values   |    default     |
| :--------: | :---------------: | :------------: |
| `opslimit` | Symbol \| Integer | `:interactive` |
| `memlimit` | Symbol \| Integer | `:interactive` |

Allowed symbol values are `:interactive`, `:moderate` and `:sensitive` as described in [RbNaCl documentation](https://rubydoc.info/github/rubycrypto/rbnacl/RbNaCl%2FPasswordHash%2FArgon2:initialize).

You most likely do not want to use the `:interactive` default in production. See [libsodium's documentation](https://libsodium.gitbook.io/doc/~/revisions/-LL5wcLSbESuQhMZUBZo/password_hashing/the_argon2i_function#guidelines-for-choosing-the-parameters) for parameter guidance.

### Version 3, PBKDF2 Parameters

|    param     | allowed values |  default  |
| :----------: | :------------: | :-------: |
| `iterations` |    Integer     | `100_000` |

As with the Version 4 parameters above, you most likely do not want to use the default value and should pick an `iterations` value with time objectives similar to the argon2 guidance.

# Registered Claims

PASETO [reserves some claim names](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) for particular use in the protocol, and this gem supports verification of all reserved claims.

In the default configuration, the following claims are verified when present: `exp`, `nbf` and `iat`

Verification behavior can be controlled by passing a kwarg for the setting to `decode` calls, or through library-level configuration.

## Default Configuration

See the appropriate section below for more information on configuring each `verify_foo`.

```ruby
Paseto.configure do |config|
  # Controls the behavior of footer deserialization in Result objects.
  # Paseto::Serializer::Raw is the other built-in option,
  # but is incompatible with registered claim validation.
  config.footer_serializer = Paseto::Serializer::OptionalJson

  config.verify_exp = true
  config.verify_nbf = true
  config.verify_iat = true

  config.verify_iss = false
  config.verify_aud = false
  config.verify_sub = false
  config.verify_jti = false
end
```

## Audience Claim

| claim type |           config type            | default |
| :--------: | :------------------------------: | :-----: |
|   String   | False \| String \| Array[String] | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { aud: 'example.com', data: 'data' }
payload = crypt.encode(hash)

audience = 'some.example.com'
crypt.decode(payload, verify_aud: audience) # => Paseto::InvalidAudience

audience = ['some.example.com', 'another.example.com', 'example.com']
crypt.decode(payload, verify_aud: audience) # => { 'aud' => ... }
```

## Expiration Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
|  DateTime  |   Boolean   | `true`  |

```ruby
crypt = Paseto::V4::Local.generate
# Override the default value by specifying a new value in your hash
hash = { exp: (Time.now - 1).iso8601, data: 'data' }
payload = crypt.encode(hash)

crypt.decode(payload) # => Paseto::ExpiredToken

crypt.decode(payload, verify_exp: false) # { 'exp' => ... }
```

## Issued At Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
|  DateTime  |   Boolean   | `true`  |

```ruby
crypt = Paseto::V4::Local.generate
# Override the default value by specifying a new value in your hash
hash = { iat: (Time.now + 5).iso8601, data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode(payload) # => Paseto::ImmatureToken

crypt.decode(payload, verify_iat: false) # { 'iat' => ... }
```

### Issuer Claim

| claim type |             config type             | default |
| :--------: | :---------------------------------: | :-----: |
|   String   | Boolean \| String \| Regexp \| Proc | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { iss: 'example.com', data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode(payload, verify_iss: 'not.example.com') # => Paseto::InvalidIssuer
```

You may also pass a Regexp or Proc with arity 1, and verification will succeed if the regexp matches or the proc returns truthy.

```ruby
issuer = /\Aexample\.com\z/
crypt.decode(payload, verify_issuer: issuer) # { 'iss' => ... }

issuer_proc = ->(iss) { iss.end_with?('example.com') }
crypt.decode(payload, verify_issuer: issuer_proc) # { 'iss' => ... }

# or verify only presence
crypt.decode(payload, verify_issuer: true) # { 'iss' => ... }
```

### Not Before Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
|  DateTime  |   Boolean   | `true`  |

```ruby
crypt = Paseto::V4::Local.generate
# Override the default value by specifying a new value in your hash
hash = { nbf: (Time.now + 5).iso8601, data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode(payload) # => Paseto::InactiveToken
crypt.decode(payload, verify_nbf: false) # => { 'nbf' => ... }
```

### Subject Claim

| claim type |   config type   | default |
| :--------: | :-------------: | :-----: |
|   String   | False \| String | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { sub: 'example.com', data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode(payload, verify_sub: 'example.com') # { 'sub' => ... }
crypt.decode(payload, verify_sub: 'example.org') # => Paseto::InvalidSubject
```

### Token Identifier Claim

| claim type |        config type        | default |
| :--------: | :-----------------------: | :-----: |
|   String   | Boolean \| String \| Proc | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { data: 'data' }
payload = crypt.encode(hash)

# Require presence
crypt.decode(payload, verify_jti: true)) # => Paseto::InvalidTokenIdentifier

# Require exact value
hash[:jti] = 'foo'
payload = crypt.encode(payload: hash)
crypt.decode(payload, verify_jti: 'foo')) # { 'data' => ... }
crypt.decode(payload, verify_jti: 'bar')) # Paseto::InvalidTokenIdentifier

# Or something more complex
jti_proc = ->(jti) { jti == 'bar'}
crypt.decode(payload, verify_jti: jti_proc)) # Paseto::InvalidTokenIdentifier
```

## Development

This repository includes a [VSCode DevContainer](.devcontainer) configuration which automatically includes extensions for both Sorbet and Solargraph, and configures a docker image with libsodium.

After checking out the repo, run `bin/setup` to install dependencies. If you are using the provided DevContainer, this happens automatically after the container image is first created.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

You can also run `bin/console` for an interactive prompt that will allow you to experiment.

### Type Checking

`paseto` uses `sorbet` to provide both static and runtime type checking.

You can learn more over at the `sorbet` [documentation](https://sorbet.org/docs/overview).

### Running Tests

The tests are written with rspec. [Appraisal](https://github.com/thoughtbot/appraisal) is used to ensure compatibility with 3rd party dependencies providing cryptographic features.

```sh
bundle install
appraisal install
# in parallel
appraisal rake
# or not
appraisal rake specs
```

### Updating RBI Files

To check that RBI files for gems are up-to-date:

```sh
appraisal rbnacl bin/tapioca gems --verify
```

To update RBI files for gems:

```sh
appraisal rbnacl bin/tapioca gems
appraisal rbnacl bin/tapioca annotations
```

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/bannable/paseto).

This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](LICENSE.txt).

## Code of Conduct

Everyone interacting in the Paseto project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
