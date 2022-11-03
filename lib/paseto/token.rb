# frozen_string_literal: true

module Paseto
  class Token
    # @dynamic version, purpose, payload, footer
    attr_reader :version
    attr_reader :purpose
    attr_reader :payload
    attr_reader :footer

    def self.parse(str)
      version, purpose, payload, footer = str.split('.')

      raise ParseError, "not a valid token" unless version && purpose

      payload = Paseto.decode64(payload || '')
      footer = Paseto.decode64(footer || '')
      
      new(version: version,
          purpose: purpose,
          payload: payload,
          footer: footer)
    end

    def initialize(payload:, purpose:, version:, footer: '')
      @version = version
      @purpose = purpose
      @payload = payload
      @footer = footer
    end

    def to_s
      parts = [version, purpose, Paseto.encode64(payload)]
      parts << Paseto.encode64(footer) unless footer.empty?
      parts.join('.')
    end
  end
end
