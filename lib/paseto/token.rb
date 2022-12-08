# typed: strict
# frozen_string_literal: true

module Paseto
  class Token
    extend T::Sig
    include Comparable

    sig { returns(String) }
    attr_reader :version, :purpose, :raw_payload, :footer

    sig { returns(T.class_of(Interface::Key)) }
    attr_reader :type

    sig { params(str: String).returns(Token) }
    def self.parse(str)
      case str.split('.')
      in [String => version, String => purpose, String => payload, String => footer]
        nil
      in [String => version, String => purpose, String => payload]
        footer = ''
      else
        raise ParseError, 'not a valid token'
      end

      payload = Util.decode64(payload)
      footer = Util.decode64(footer)

      new(version: version, purpose: purpose, payload: payload, footer: footer)
    end

    sig { params(payload: String, purpose: String, version: String, footer: String).void }
    def initialize(payload:, purpose:, version:, footer: '')
      @version = T.let(version.freeze, String)
      @purpose = T.let(purpose.freeze, String)
      @raw_payload = T.let(payload.freeze, String)
      @payload = T.let(nil, T.nilable(T::Hash[String, T.untyped]))
      @footer = T.let(footer.freeze, String)
      @type = T.let(validate_header, T.class_of(Interface::Key))

      raw = [version, purpose, Util.encode64(raw_payload)]
      raw << Util.encode64(footer) unless footer.empty?
      @str = T.let(raw.join('.').freeze, String)
    end

    sig do
      params(
        key: Interface::Key,
        implicit_assertion: String,
        options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
      ).returns(T::Hash[String, T.untyped])
    end
    def decode!(key, implicit_assertion: '', **options)
      key.decode(@str, implicit_assertion: implicit_assertion, **options)
      .then { |result| @payload = result.claims }
    end

    sig { returns(String) }
    def header
      "#{version}.#{purpose}"
    end

    sig { returns(String) }
    def inspect
      to_s
    end

    sig { returns(T::Hash[String, T.untyped]) }
    def payload
      return @payload if @payload
      raise ParseError, 'token not yet decoded, call #decode! first'
    end

    sig { returns(String) }
    def to_s = @str

    sig { params(other: T.any(Token, String)).returns(T.nilable(Integer)) }
    def <=>(other)
      to_s <=> other.to_s
    end

    private

    sig { returns(T.class_of(Interface::Key)) }
    def validate_header
      type = TokenTypes.deserialize(header).key_klass
      return type if type

      raise UnsupportedToken, header
    rescue KeyError
      raise UnsupportedToken, header
    end
  end
end
