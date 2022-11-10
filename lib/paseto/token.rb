# frozen_string_literal: true

module Paseto
  class Token
    include Comparable

    # @dynamic version, purpose, payload, footer
    attr_reader :version
    attr_reader :purpose, :payload, :footer

    def self.parse(str)
      case str.split(".")
      in [String => version, String => purpose, String => payload]
        footer = ""
      in [String => version, String => purpose, String => payload, String => footer]
        nil
      else
        raise ParseError, "not a valid token"
      end

      payload = Util.decode64(payload)
      footer = Util.decode64(footer)

      begin
        new(version:, purpose:, payload:, footer:)
      rescue ArgumentError
        raise ParseError, "not a valid token"
      end
    end

    def initialize(payload:, purpose:, version:, footer: "")
      @version = version
      @purpose = purpose
      @payload = payload
      @footer = footer
      raise ArgumentError, "not a valid token" unless valid?
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

    private

    def valid?
      case version
      when "v3", "v4"
        %w[local public].include? purpose
      else
        false
      end
    end
  end
end
