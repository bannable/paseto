# typed: strict
# encoding: binary
# frozen_string_literal: true

module Paseto
  class Key
    extend T::Sig

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
  end
end
