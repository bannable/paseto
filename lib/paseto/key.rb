# encoding: binary
# frozen_string_literal: true

module Paseto
  class Key
    def initialize(version:, purpose:)
      @version = version
      @purpose = purpose
    end

    attr_reader :version, :purpose

    def header
      "#{version}.#{purpose}"
    end
  end
end
