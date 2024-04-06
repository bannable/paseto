# typed: strict
# frozen_string_literal: true

module Paseto
  class Token
    extend T::Sig
    include Comparable

    sig { returns(String) }
    attr_reader :version, :purpose, :raw_payload, :raw_footer

    sig { returns(T.any(String, T::Hash[String, T.untyped])) }
    attr_reader :footer

    sig { returns(T.class_of(Interface::Key)) }
    attr_reader :type

    sig do
      params(
        paseto: String,
        options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
      ).returns(Token)
    end
    def self.parse(paseto, **options)
      case paseto.split('.')
      in [String => version, String => purpose, String => payload, String => footer]
        nil
      in [String => version, String => purpose, String => payload]
        footer = ''
      else
        raise ParseError, 'not a valid token'
      end

      payload = Util.decode64(payload)
      Util.decode64(footer)
          .then { |f| serializer.deserialize(f, options) }
          .then { |f| new(version:, purpose:, payload:, footer: f) }
    end

    sig { returns(Paseto::Interface::Serializer) }
    def self.serializer
      Paseto.config.decode.footer_serializer
    end

    sig do
      params(
        payload: String,
        purpose: String,
        version: String,
        footer: T.any(String, T::Hash[String, T.untyped]),
        options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
      ).void
    end
    def initialize(payload:, purpose:, version:, footer: '', **options) # rubocop:disable Metrics/AbcSize
      raw_footer = serializer.serialize(footer, options)
      encoded_footer = ".#{Util.encode64(raw_footer)}" unless raw_footer.empty?

      paseto = Util.encode64(payload)
                   .then { |data| "#{data}#{encoded_footer}" }
                   .then { |data| "#{version}.#{purpose}.#{data}" }
                   .then(&:freeze)

      @version =     T.let(version.freeze,             String)
      @purpose =     T.let(purpose.freeze,             String)
      @raw_payload = T.let(payload.freeze,             String)
      @type =        T.let(validate_header,            T.class_of(Interface::Key))
      @footer =      T.let(footer,                     T.any(String, T::Hash[String, T.untyped]))
      @raw_footer =  T.let(raw_footer,                 String)
      @str =         T.let(paseto,                     String)
    end

    sig do
      params(
        key: Interface::Key,
        implicit_assertion: String,
        options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
      ).returns(T::Hash[String, T.untyped])
    end
    def decode!(key, implicit_assertion: '', **options)
      return @result.claims if @result

      key.decode(@str, implicit_assertion:, **options)
         .then { |result| @result = T.let(result, T.nilable(Result)) }
         .then(&:claims)
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
      return @result.claims if @result

      raise ParseError, 'token not yet decoded, call #decode! first'
    end

    sig { returns(String) }
    def to_s = @str

    sig { params(other: T.any(Token, String)).returns(T.nilable(Integer)) }
    def <=>(other)
      to_s <=> other.to_s
    end

    private

    sig { returns(Paseto::Interface::Serializer) }
    def serializer = self.class.serializer

    sig { returns(T.class_of(Interface::Key)) }
    def validate_header
      type = begin
        TokenTypes.deserialize(header).key_klass
      rescue KeyError
        nil
      end

      type or raise UnsupportedToken, header
    end
  end
end
