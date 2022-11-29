# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    module PBKD
      class PBKDv4
        extend T::Sig

        DOMAIN_SEPARATOR_ENCRYPT = T.let("\xFF".b, String)
        DOMAIN_SEPARATOR_AUTH = T.let("\xFE".b, String)

        include Interface::PBKD

        sig { override.returns(Protocol::Version4) }
        def protocol
          Protocol::Version4.new
        end

        sig { params(password: String).void }
        def initialize(password)
          @password = password
        end

        sig { override.returns(String) }
        def local_header
          'k4.local-pw.'
        end

        sig { override.returns(String) }
        def secret_header
          'k4.secret-pw.'
        end

        sig do
          override.params(
            key: Key,
            options: T::Hash[Symbol, Integer]
          ).returns(String)
        end
        def wrap(key, options)
          options => {memlimit:, opslimit:}

          header = pbkw_header(key)
          nonce = RbNaCl::Random.random_bytes(24)
          salt = RbNaCl::Random.random_bytes(16)
          pre_key = RbNaCl::PasswordHash.argon2id(@password, salt, opslimit, memlimit, 32)
          ek = RbNaCl::Hash.blake2b("#{DOMAIN_SEPARATOR_ENCRYPT}#{pre_key}", digest_size: 32)
          ak = RbNaCl::Hash.blake2b("#{DOMAIN_SEPARATOR_AUTH}#{pre_key}", digest_size: 32)

          edk = Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(nonce, key.to_bytes)

          message = [salt, Util.int_to_be64(memlimit), Util.int_to_be32(opslimit), Util.int_to_be32(1), nonce, edk].join
          t = RbNaCl::Hash.blake2b("#{header}#{message}", key: ak, digest_size: 32)

          [header, Util.encode64("#{message}#{t}")].join
        end

        sig { override.params(header: String, data: String).returns(Key) }
        def unwrap(header, data)
          h = pbkw_header(header)

          decode(data) => {salt:, memlimit:, opslimit:, nonce:, para:, edk:, tag:}

          k = RbNaCl::PasswordHash.argon2id(@password, salt, Util.be32_to_int(opslimit), Util.be64_to_int(memlimit), 32)

          ak = RbNaCl::Hash.blake2b("#{DOMAIN_SEPARATOR_AUTH}#{k}", digest_size: 32)

          message = "#{h}#{salt}#{memlimit}#{opslimit}#{para}#{nonce}#{edk}"
          t2 = RbNaCl::Hash.blake2b(message, key: ak, digest_size: 32)
          raise InvalidAuthenticator unless Util.constant_compare(t2, tag)

          ek = RbNaCl::Hash.blake2b("#{DOMAIN_SEPARATOR_ENCRYPT}#{k}", digest_size: 32)
          ptk = Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(nonce, edk)

          PaserkTypes.deserialize(header).generate(ptk)
        end

        private

        sig { params(lookup: T.any(Key, String)).returns(String) }
        def pbkw_header(lookup)
          case lookup
          when Interface::Symmetric, 'k4.local-pw' then local_header
          when Interface::Asymmetric, 'k4.secret-pw' then secret_header
          else
            # :nocov:
            raise ArgumentError, 'not a valid type of key'
            # :nocov:
          end
        end

        sig do
          params(payload: String)
            .returns(
              {
                salt: String,
                memlimit: String,
                opslimit: String,
                para: String,
                nonce: String,
                edk: String,
                tag: String
              }
            )
        end
        def decode(payload)
          data = Util.decode64(payload)
          edk_len = data.bytesize - 88
          {
            salt: T.must(data.byteslice(0, 16)),
            memlimit: T.must(data.byteslice(16, 8)),
            opslimit: T.must(data.byteslice(24, 4)),
            para: T.must(data.byteslice(28, 4)),
            nonce: T.must(data.byteslice(32, 24)),
            edk: T.must(data.byteslice(56, edk_len)),
            tag: T.must(data.byteslice(-32, 32))
          }
        end
      end
    end
  end
end
