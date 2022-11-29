# encoding: binary
# typed: true
# frozen_string_literal: true

module Paseto
  class Key
    extend T::Sig
    extend T::Helpers

    DOMAIN_SEPARATOR_AUTH = "\x81"
    DOMAIN_SEPARATOR_ENCRYPT = "\x80"

    abstract!

    sig { abstract.returns(String) }
    def purpose; end

    sig { abstract.returns(String) }
    def to_bytes; end

    sig { abstract.returns(Interface::Version) }
    def protocol; end

    sig(:final) { returns(String) }
    def version
      protocol.version
    end

    sig(:final) { returns(String) }
    def paserk_version
      protocol.paserk_version
    end

    sig(:final) { returns(String) }
    def header
      "#{version}.#{purpose}"
    end

    sig(:final) { returns(String) }
    def pae_header
      "#{header}."
    end
  end
end
