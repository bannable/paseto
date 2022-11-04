# encoding: binary
# frozen_string_literal: true

module Paseto
  class Key
    def self.keysize
      raise NotImplementedError
    end

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

    private

    def key
      @key
    end
  end
end
