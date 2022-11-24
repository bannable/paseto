# typed: strict
# frozen_string_literal: true

module Paseto
  module Paserk
    extend T::Sig
    extend T::Helpers

    class Error < Paseto::Error; end

    class UnrecognizedProtocol < Error; end

    requires_ancestor { Kernel }

    sig do
      params(
        paserk: String,
        wrapping_key: T.nilable(String),
        password: T.nilable(String),
        unsealing_key: T.nilable(String)
      ).returns(T.untyped)
    end
    def self.from_paserk(paserk:, wrapping_key: nil, password: nil, unsealing_key: nil)
      case paserk.split('.')
      in [String => version, String => type, String => protocol, String => data] if wrapping_key
        # Symmetric Key Wrapping
        # local/secret-wrap
        # https://github.com/paseto-standard/paserk/blob/master/operations/Wrap.md
        raise Paserk::UnrecognizedProtocol unless protocol == 'pie'

        PIE.unwrap(version, type, T.must(wrapping_key), data)
      in [String => version, String => type, String => data] if password
        # local/secret-pw
      in [String => version, String => type, String => data] if unsealing_key
        # seal
      else
        raise UnrecognizedProtocol
      end
    end

    sig { params(key: Key, wrapping_key: String, nonce: T.nilable(String)).returns(String) }
    def self.wrap(key:, wrapping_key:, nonce: nil)
      PIE.wrap(key, wrapping_key: wrapping_key, nonce: nonce)
    end
  end
end
