# Paseto
[![Ruby Style Guide](https://img.shields.io/badge/code_style-community-brightgreen.svg)](https://rubystyle.guide)

This is an implementation of the [PASETO token protocol](https://github.com/paseto-standard/paseto-spec), written in Ruby, which supports versions [v3](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-3-nist-modern) and [v4](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-4-sodium-modern). This library passes all [official test vectors](https://github.com/paseto-standard/test-vectors) for supported versions and purposes.

Additionally, the library uses [Sorbet](https://sorbet.org) to enforce types at runtime.

## Installing

### libsodium

This gem requires libsodium `1.0.0` or newer. You can find instructions for obtaining libsodium at https://libsodium.org.

### Using Bundler:

Add the following to your Gemfile:
```
gem 'paseto', git: 'git://github.com/bannable/paseto.git'
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

`paseto` does not yet support [PASERK (Platform-Agnostic Serialized Keys)](https://github.com/paseto-standard/paserk), but will in the future!
<!--

|               |  v4  |  v3  |
| ------------- | ---- | ---- |
| `lid`         |  ❌  |  ❌  |
| `sid`         |  ❌  |  ❌  |
| `pid`         |  ❌  |  ❌  |
| `local`       |  ❌  |  ❌  |
| `secret`      |  ❌  |  ❌  |
| `public`      |  ❌  |  ❌  |
| `seal`        |  ❌  |  ❌  |
| `local-wrap`  |  ❌  |  ❌  |
| `secret-wrap` |  ❌  |  ❌  |
| `local-pw`    |  ❌  |  ❌  |
| `secret-pw`   |  ❌  |  ❌  |
-->
## Implementation Guideline compliance

- [ ] require payload to be UTF-8 encoded
- [ ] enforce JSON encoding of payload
  - [ ] require topmost object to be an object, map, or associative array
- [ ] protect against loading off-curve public keys
- [ ] support "expected footer" inputs during public#verify and local#decrypt operations
- [ ] support for [Validators](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md)
- [ ] protect against arbitrary/invalid data in [Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md)
- [ ] [Key-ID support](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#key-id-support)

## Usage

### The Paseto::Token

A `Token` is used for (de)serialization of token inputs, and is returned by any `encrypt` or `sign` operation. `Token` instances may be compared with token strings.

```ruby
input = "v4.public.eyJmb28iOiJiYXIifb2eGqFF-PysuYUWeXq2FIYVfkuW5qcCuwPE4RpM1qzPCS7vEV9IXzDTwcFroCO-7cFZO1NAI5AU-NOsirny_wM.YmF6"
token = Paseto::Token.parse(input)
token.version  # => "v4"
token.purpose  # => "local"
token.header   # => "v4.local"
token.footer   # => "baz"
token.payload  # => Base64 decoded payload
token.to_s     # => "v4.public.eyJmb28iOiJiYXIifb2eGqFF-PysuYUWeXq2FIYV..."
token.inspect  # => "v4.public.eyJmb28iOiJiYXIifb2eGqFF-PysuYUWeXq2FIYV..."
puts token     # => v4.public.eyJmb28iOiJiYXIifb2eGqFF-PysuYUWeXq2FIYV...
token == input # => true
token == "foo" # => false
input == token # => false, library does not modify String behavior
```

### PASETO v4, Sodium Modern

[Description](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#version-4-nist-modern) and [Specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md).

#### Encryption and Decryption

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
# or initialize from a seed
signer = Paseto::V4::Public.new(private_key: signer.private_key.to_s)

token = signer.sign(message: '{"foo":"bar"}') # => Token("v4.public....")
token = signer.sign(message: '{"foo":"bar"}', footer: '', implicit_assertion: '') # same as above
signer.verify(token:) # => '{"foo":"bar"}'

# or initialize only for verification
verifier = Paseto::V4::Public.new(public_key: signer.public_key.to_s)
verifier.verify(token:) # => '{"foo":"bar"}'
verifier.verify(token:, implicit_assertion: '') # same as above
verifier.sign(message: '{"foo":"bar"}') # => ArgumentError

# exporting key material
signer.private_key.to_s # => Ed25519 private key octet string seed
signer.public_key.to_s  # => Ed25519 public key octet string seed
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
# or initialize from a PEM or DER encoded key
signer = Paseto::V3::Public.new(key: signer.private_key.to_der)

token = signer.sign(message: '{"foo":"bar"}') # => Token("v3.public....")
token = signer.sign(message: '{"foo":"bar"}', footer: '', implicit_assertion: '') # same as above
signer.verify(token:) # => '{"foo":"bar"}'

# or initialize only for verification
verifier = Paseto::V3::Public.new(key: signer.public_key.to_s)
verifier.verify(token:) # => '{"foo":"bar"}'
verifier.verify(token:, implicit_assertion: '') # same as above
verifier.sign(message: '{"foo":"bar"}') # => ArgumentError

# exporting key material
signer.key.public_to_pem # => PEM encoded public key
signer.key.private_to_pem # => PEM encoded private key
signer.key.public_to_der # => DER encoded public key
signer.key.private_to_der # => DER encoded private key
```

## Development

This repository includes a [VSCode DevContainer](.devcontainer) configuration which automatically includes extensions for both Sorbet and Solargraph, and configures a docker image with libsodium.

After checking out the repo, run `bin/setup` to install dependencies.

If you are using the provided DevContainer, this happens automatically after the container image is first created. You may need to restart Solargraph for it to work correctly when first bringing up the container.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

You can also run `bin/console` for an interactive prompt that will allow you to experiment.

### Type Checking

`paseto` uses `sorbet` to provide both static and runtime type checking.

You can learn more over at the `sorbet` [documentation](https://sorbet.org/docs/overview).

### Running Tests

```
rspec
rubocop
srb tc
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
