# encoding: binary
# frozen_string_literal: true

module Paseto
  class Key
    def initialize(version:, purpose:)
      @version = version
      @purpose = purpose
    end

    def version
      @version
    end

    def purpose
      @purpose
    end

    def header
      "#{version}.#{purpose}"
    end
  end
end
