# encoding: binary
# typed: true
# frozen_string_literal: true

module Paseto
  class Key
    extend T::Sig
    extend T::Helpers

    include Interface::Version

    DOMAIN_SEPARATOR_AUTH = "\x81"
    DOMAIN_SEPARATOR_ENCRYPT = "\x80"

    abstract!

    sig { returns(String) }
    attr_reader :purpose

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
  end
end
