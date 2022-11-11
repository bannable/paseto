# typed: true
# encoding: binary
# frozen_string_literal: true

module Paseto
  class Key
    def initialize(version:, purpose:)
      @version = version
      @purpose = purpose
    end

    # @dynamic version, purpose

    attr_reader :version, :purpose

    def header
      "#{version}.#{purpose}"
    end

    def pae_header
      "#{header}."
    end
  end
end
