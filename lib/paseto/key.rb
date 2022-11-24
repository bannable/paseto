# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  class Key
    extend T::Sig
    extend T::Helpers

    DOMAIN_SEPARATOR_AUTH = "\x81"
    DOMAIN_SEPARATOR_ENCRYPT = "\x80"

    abstract!

    sig { params(paserk: String, wrapping_key: String).returns(Key) }
    def self.unwrap(paserk:, wrapping_key:)
      Paserk.from_paserk(paserk: paserk, wrapping_key: wrapping_key)
    end

    sig { params(version: String, purpose: String).void }
    def initialize(version:, purpose:)
      @version = version
      @purpose = purpose
    end

    sig { returns(String) }
    attr_reader :version, :purpose

    sig { returns(String) }
    def header
      "#{version}.#{purpose}"
    end

    sig { returns(String) }
    def pae_header
      "#{header}."
    end

    sig { abstract.returns(String) }
    def to_bytes; end

    sig { params(wrapping_key: String, nonce: T.nilable(String)).returns(String) }
    def wrap(wrapping_key, nonce: nil)
      Paserk.wrap(key: self, wrapping_key: wrapping_key, nonce: nonce)
    end

    private
  end
end
