# encoding: binary
# frozen_string_literal: true

module Paseto
  class Key
    def self.keysize
      raise NotImplementedError
    end

    def initialize(version:, purpose:, secret_key:, public_key: nil)
      @version = version
      @purpose = purpose
      @secret_key = secret_key
      @public_key = public_key
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

    def public_key
      @public_key
    end

    private

    def secret_key
      @secret_key
    end
  end
end
