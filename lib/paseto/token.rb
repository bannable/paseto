# typed: strict
# frozen_string_literal: true

module Paseto
  class Token
    extend T::Sig
    include Comparable

    sig { returns(String) }
    attr_reader :version, :purpose, :payload, :footer

    sig { params(str: String).returns(Token) }
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

      new(version:, purpose:, payload:, footer:)
    end

    sig { params(payload: String, purpose: String, version: String, footer: String).void }
    def initialize(payload:, purpose:, version:, footer: "")
      @version = version
      @purpose = purpose
      @payload = payload
      @footer = footer
      raise ParseError, "not a valid token" unless valid?
    end

    sig { returns(String) }
    def header
      "#{version}.#{purpose}"
    end

    sig { returns(String) }
    def to_s
      parts = [version, purpose, Util.encode64(payload)]
      parts << Util.encode64(footer) unless footer.empty?
      parts.join(".")
    end

    sig { returns(String) }
    def inspect
      to_s
    end

    sig { params(other: T.any(Token, String)).returns(T.nilable(Integer)) }
    def <=>(other)
      to_s <=> other.to_s
    end

    private

    sig { returns(T::Boolean) }
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
