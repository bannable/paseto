# typed: strict
# frozen_string_literal: true

module Paseto
  module Paserk
    extend T::Sig
    extend T::Helpers

    requires_ancestor { Kernel }

    sig do
      params(
        paserk: String,
        wrapping_key: T.nilable(SymmetricKey),
        password: T.nilable(String),
        unsealing_key: T.nilable(AsymmetricKey)
      ).returns(T.untyped)
    end
    def self.from_paserk(paserk:, wrapping_key: nil, password: nil, unsealing_key: nil)
      parts = paserk.split('.')
      case parts
      in [String => version, String => type, String => protocol, String => data] if wrapping_key
        Operations::Wrap.unwrap(T.must(wrapping_key), [version, type, protocol, data])

      in [String => version, String => type, String => data] if password
        version = Versions.deserialize(version).instance
        Operations::PBKW.new(version, T.must(password)).decode(paserk)

      in [String => version, String => type, String => data] if unsealing_key
        Operations::PKE.new(T.must(unsealing_key)).decode(paserk)

      in [String => version, String => type, String => data] if %w[local secret public].include?(type)
        PaserkTypes.deserialize(paserk.rpartition('.').first).generate(Util.decode64(data))

      else
        raise UnknownOperation
      end
    end

    sig { params(key: Interface::Key, wrapping_key: SymmetricKey, nonce: T.nilable(String)).returns(String) }
    def self.wrap(key:, wrapping_key:, nonce: nil)
      Operations::Wrap.wrap(key, wrapping_key: wrapping_key, nonce: nonce)
    end

    sig { params(key: Interface::Key, password: String, options: T::Hash[Symbol, T.any(Integer, Symbol)]).returns(String) }
    def self.pbkw(key:, password:, options: {})
      Operations::PBKW.pbkw(key, password, options)
    end

    sig { params(key: SymmetricKey, sealing_key: AsymmetricKey).returns(String) }
    def self.seal(key:, sealing_key:)
      Operations::PKE.new(sealing_key).encode(key)
    end
  end
end
