# Paseto
[![Ruby Style Guide](https://img.shields.io/badge/code_style-community-brightgreen.svg)](https://rubystyle.guide) [![CircleCI](https://dl.circleci.com/status-badge/img/gh/bannable/paseto/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/bannable/paseto/tree/main) [![Maintainability](https://api.codeclimate.com/v1/badges/0bc8fcc6751880b68a9c/maintainability)](https://codeclimate.com/github/bannable/paseto/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/0bc8fcc6751880b68a9c/test_coverage)](https://codeclimate.com/github/bannable/paseto/test_coverage)

This is an implementation of the [PASETO token protocol](https://github.com/paseto-standard/paseto-spec), written in Ruby, which supports versions [v3](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-3-nist-modern) and [v4](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-4-sodium-modern). This library passes all [official test vectors](https://github.com/paseto-standard/test-vectors) for supported versions and purposes.

Additionally, the library uses [Sorbet](https://sorbet.org) to enforce types at runtime.

## Installing

### RbNaCl and libsodium

**Optional for v4.local tokens support**: Handling v4.local tokens requires [`RbNaCl`](https://github.com/RubyCrypto/rbnacl) with `libsodium 1.0.0` or newer.

You can find instructions for obtaining libsodium at https://libsodium.org.

If you do not intend to create or parse `v4.local` tokens, feel free to skip this dependency.

### Using Bundler:

Add the following to your Gemfile:
```
gem 'paseto', git: 'git://github.com/bannable/paseto.git'
# and optionally:
gem 'rbnacl', '~> 7.1.1'
```

And run `bundle install`.
<!--
### Using Rubygems:
```bash
gem install paseto
```

### Using Bundler:
Add the following to your Gemfile
```
gem 'paseto'
```
And run `bundle install`

-->
## Supported PASETO versions

`paseto` supports these PASETO versions and purposes:
|          |  v4  |  v3  |
| ---------| ---- | ---- |
| `local`  |  ✅  |  ✅  |
| `public` |  ✅  |  ✅  |

## Support for PASERK types

[PASERK (Platform-Agnostic Serialized Keys)](https://github.com/paseto-standard/paserk), support is a Work In Progress.

|               |  v4  |  v3  |
| ------------- | ---- | ---- |
| `lid`         |  ❌  |  ❌  |
| `sid`         |  ❌  |  ❌  |
| `pid`         |  ❌  |  ❌  |
| `local`       |  ✅  |  ✅  |
| `secret`      |  ✅  |  ✅  |
| `public`      |  ✅  |  ✅  |
| `seal`        |  ❌  |  ❌  |
| `local-wrap`  |  ✅  |  ✅  |
| `secret-wrap` |  ✅  |  ✅  |
| `local-pw`    |  ✅  |  ✅  |
| `secret-pw`   |  ✅  |  ✅  |

## Implementation Guideline compliance

- [x] require payload to be UTF-8 encoded
- [x] enforce JSON encoding of payload
  - [x] require topmost object to be an object, map, or associative array
- [x] protect against loading off-curve public keys
- [ ] support "expected footer" inputs during public#verify and local#decrypt operations
- [x] support for [Validators](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md)
- [ ] protect against arbitrary/invalid data in [Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md)
- [ ] [Key-ID support](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#key-id-support)

## Usage

```ruby
signer = Paseto::V3::Public.generate
encrypter = Paseto::V4::Local.generate

h = { "foo" => "bar", "baz" => 1 }
signed_token = signer.encode(payload: h) # => v3.public...
encrypted_token = encrypter.encode(payload: h) # => v4.local...

signer.decode(payload: signed_token) # => {"foo"=>"bar", "baz"=>1}
encrypter.decode(payload: encrypted_token) # => {"foo"=>"bar", "baz"=>1}
encrypter.decode(payload: signed_token) # => Paseto::ParseError
```
The `encode` and `decode` interfaces ensure that your token payloads always comply with the [PASETO Payload Processing guidelines](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md).

This library uses `multi_json` to provide serialization and deserialization, so you may configure your adapter as you please.

If you want to handle serialization and claim verification yourself, you may instead use `encrypt`/`decrypt` and `sign`/`verify`.

```ruby
# You may pass JSON adapter options to encode and decode
encrypter.decode(payload: encrypted_token, symbolize_keys: true) # => {:foo => "bar", :baz => 1}
# Or setting default options with Oj
Oj.default_options = {symbol_keys: true}
encrypter.decode(payload: encrypted_token) # => {:foo => "bar", :baz => 1}
```

You may optionally enforce validation of claims by calling `decode!` instead of `decode`. See [Registered Claims](#registered-claims-support) for more information on configuration validation.

### PASETO v4, Sodium Modern

[Description](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-4-nist-modern) and [Specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md).

#### Encryption and Decryption

V4 encryption with `paseto` uses the XChaCha20 stream cipher provided by libsodium, and requires the `RbNaCl` gem.

To use `v4.local` tokens, ensure that `rbnacl` is installed.


```ruby
crypt = Paseto::V4::Local.generate
# or initialize with a known key
ikm = SecureRandom.bytes(32)
crypt = Paseto::V4::Local.new(ikm:)

token = crypt.encrypt(message: '{"foo":"bar"}') # => Token("v4.local....")
token = crypt.encrypt(message: '{"foo":"bar"}', footer: '', implicit_assertion: '') # same as above
crypt.decrypt(token:) # => '{"foo":"bar"}'

# exporting key material
crypt.key # => ikm
```

#### Message Signing and Verification

```ruby
signer = Paseto::V4::Public.generate # => Paseto::V4::Public
# or initialize from a DER- or PEM-encoded input
pem = File.read('my.pem')
signer = Paseto::V4::Public.new(key: pem)

token = signer.sign(message: '{"foo":"bar"}') # => Token("v4.public....")
token = signer.sign(message: '{"foo":"bar"}', footer: '', implicit_assertion: '') # same as above
signer.verify(token:) # => '{"foo":"bar"}'

# or initialize only for verification
verifier = Paseto::V4::Public.new(public_key: signer.public_key.to_s)
verifier.verify(token:) # => '{"foo":"bar"}'
verifier.verify(token:, implicit_assertion: '') # same as above
verifier.sign(message: '{"foo":"bar"}') # => ArgumentError

# exporting key material
signer.public_to_pem # => PEM
signer.private_to_pem # => PEM
```

### PASETO v3, NIST Modern

[Description](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-3-nist-modern) and [Specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md).

#### Encryption and Decryption

```ruby
crypt = Paseto::V3::Local.generate
# or initialize with a known key
ikm = SecureRandom.bytes(32)
crypt = Paseto::V3::Local.new(ikm:)

token = crypt.encrypt(message: '{"foo":"bar"}') # => Token("v3.local....")
token = crypt.encrypt(message: '{"foo":"bar"}', footer: '', implicit_assertion: '') # same as above
crypt.decrypt(token:) # => '{"foo":"bar"}'

# exporting key material
crypt.key # => ikm
```

#### Message Signing and Verification

```ruby
signer = Paseto::V3::Public.generate # => Paseto::V4::Public
# or initialize from a PEM or DER encoded key. May be either a public or private key.
signer = Paseto::V3::Public.new(key: signer.key.private_key.to_der)

token = signer.sign(message: '{"foo":"bar"}') # => Token("v3.public....")
token = signer.sign(message: '{"foo":"bar"}', footer: '', implicit_assertion: '') # same as above
signer.verify(token:) # => '{"foo":"bar"}'

# or initialize only for verification
verifier = Paseto::V3::Public.new(key: signer.key.public_key.to_pem)
verifier.verify(token:) # => '{"foo":"bar"}'
verifier.verify(token:, implicit_assertion: '') # same as above
verifier.sign(message: '{"foo":"bar"}') # => ArgumentError

# exporting key material
signer.public_to_pem # => PEM encoded public key
signer.private_to_pem # => PEM encoded private key
```

## Registered Claims Support

PASETO [reserves some claim names](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) for particular use in the protocol. `paseto` supports verification of all reserved claims through the `decode!` interface. In the default configuration, only `exp` and `iat` claims are verified.

### Audience Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
| String | False \| String \| Array[String] | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { exp: (Time.now + 60).iso8601, iat: Time.now.iso8601, aud: 'example.com', data: 'data' }
payload = crypt.encode(payload: hash)

options = { verify_aud: 'some.example.com' }
crypt.decode!(payload:, options:) # => Paseto::InvalidAudience

options = { verify_aud: ['some.example.com', 'another.example.com', 'example.com']}
crypt.decode!(payload:, options:) # => { exp: ... }
```

### Expiration Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
| DateTime | Boolean | `true` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { exp: (Time.now - 1).iso8601, iat: (Time.now - 5).iso8601, data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode!(payload:) # => Paseto::ExpiredToken

options = { verify_exp: false }
crypt.decode!(payload:, options:) # { exp: ... }
```

### Issued At Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
| DateTime | Boolean | `true` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { exp: (Time.now + 60).iso8601, iat: (Time.now + 5).iso8601, data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode!(payload:) # => Paseto::ImmatureToken

options = { verify_iat: false }
crypt.decode!(payload:, options:) # { exp: ... }
```

### Issuer Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
| String     | Boolean \| String \| Regexp \| Proc | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { exp: (Time.now + 60).iso8601, iat: Time.now.iso8601, iss: 'example.com', data: 'data' }
payload = crypt.encode(payload: hash)

options = { verify_issuer: 'not.example.com' }
crypt.decode!(payload:, options:) # => Pseto::InvalidIssuer
```

You may also pass a Regexp or Proc with arity 1, and verification will succeed if the regexp matches or the proc returns truthy.

```ruby
opts = { verify_issuer: /\Aexample\.com\z/}
crypt.decode!(payload: options: opts) # { exp: ... }

opts = { verify_issuer: ->(iss) { iss.end_with?('example.com') } }
crypt.decode!(payload:, options: opts) # { exp: ... }

# or verify only presence
crypt.decode!(payload:, options: { verify_issuer: true }) # { exp: ... }
```

### Not Before Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
| DateTime | Boolean | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { exp: (Time.now + 60).iso8601, iat: Time.now.iso8601, nbf: (Time.now + 5).iso8601, data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode!(payload: options: { verify_nbf: true}) # => Paseto::InactiveToken
```

### Subject Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
| String | False \| String | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { exp: (Time.now + 60).iso8601, iat: Time.now.iso8601, sub: 'example.com', data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode!(payload: options: { verify_sub: 'example.com'}) # { exp: ... }
crypt.decode!(payload: options: { verify_sub: 'example.org'}) # => Paseto::InvalidSubject
```

### Token Identifier Claim

| claim type | config type | default |
| :--------: | :---------: | :-----: |
| String | Boolean \| String \| Proc | `false` |

```ruby
crypt = Paseto::V4::Local.generate
hash = { exp: (Time.now + 60).iso8601, iat: Time.now.iso8601, data: 'data' }
payload = crypt.encode(payload: hash)

crypt.decode!(payload:, options: { verify_jti: true})) # => Paseto::InvalidTokenIdentifier

hash[:jti] = 'foo'
payload = crypt.encode(payload: hash)
crypt.decode!(payload:, options: { verify_jti: 'foo'})) #  # { exp: ... }
crypt.decode!(payload:, options: { verify_jti: 'bar'})) # Paseto::InvalidTokenIdentifier

options = { verify_jti: ->(jti) { jti == 'bar'} }
crypt.decode!(payload:, options:)) # Paseto::InvalidTokenIdentifier
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

```
bundle install
bundle exec appraisal rake spec
```

### Updating RBI Files

To check that RBI files for gems are up-to-date with your Gemfile.lock:
```
bin/tapioca gems --verify
```

To update RBI files for gems:
```
bin/tapioca gems
bin/tapioca annotations
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/bannable/paseto.

This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](LICENSE.txt).

## Code of Conduct

Everyone interacting in the Paseto project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
