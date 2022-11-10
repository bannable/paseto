# frozen_string_literal: true

module Paseto
  class Token
    include Comparable

    # @dynamic version, purpose, payload, footer
    attr_reader :version
    attr_reader :purpose, :payload, :footer

    def self.parse(str)
      version, purpose, payload, footer = str.split(".")

      raise ParseError, "not a valid token" unless version && purpose

      payload = Util.decode64(payload || "")
      footer = Util.decode64(footer || "")

      new(version:,
          purpose:,
          payload:,
          footer:)
    end

    def initialize(payload:, purpose:, version:, footer: "")
      @version = version
      @purpose = purpose
      @payload = payload
      @footer = footer
    end

    def header
      "#{version}.#{purpose}"
    end

    def to_s
      parts = [version, purpose, Util.encode64(payload)]
      parts << Util.encode64(footer) unless footer.empty?
      parts.join(".")
    end

    def inspect
      to_s
    end

    def <=>(other)
      to_s <=> other.to_s
    end
  end
end
