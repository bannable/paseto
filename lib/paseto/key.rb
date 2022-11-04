# encoding: binary
# frozen_string_literal: true

module Paseto
  class Key
    def initialize(version:, purpose:, ikm:)
      @version = version
      @purpose = purpose
      @key = ikm
      @secret = true
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
    
    def secret?
      @secret
    end

    def valid_for?(version:, purpose:)
      version == @version && purpose == @purpose
    end

    private

    def key
      @key
    end
  end
end
