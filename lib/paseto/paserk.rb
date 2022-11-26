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
        wrapping_key: T.nilable(T.all(Key, Interface::Symmetric)),
        password: T.nilable(String),
        unsealing_key: T.nilable(String)
      ).returns(T.untyped)
    end
    def self.from_paserk(paserk:, wrapping_key: nil, password: nil, unsealing_key: nil)
      parts = paserk.split('.')
      case parts
      in [String => version, String => type, String => protocol, String => data] if wrapping_key
        # Symmetric Key Wrapping
        # local/secret-wrap
        # https://github.com/paseto-standard/paserk/blob/master/operations/Wrap.md
        Operations::Wrap.unwrap(T.must(wrapping_key), [version, type, protocol, data])
      in [String => version, String => type, String => data] if password
      # local/secret-pw
      in [String => version, String => type, String => data] if unsealing_key
        # seal
      else
        raise UnknownOperation
      end
    end

    sig { params(key: Key, wrapping_key: T.all(Key, Interface::Symmetric), nonce: T.nilable(String)).returns(String) }
    def self.wrap(key:, wrapping_key:, nonce: nil)
      Operations::Wrap.wrap(key, wrapping_key: wrapping_key, nonce: nonce)
    end
  end
end
