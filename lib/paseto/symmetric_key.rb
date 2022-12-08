# typed: strict
# frozen_string_literal: true

module Paseto
  class SymmetricKey < Interface::Key
    extend T::Sig
    extend T::Helpers

    abstract!

    sig(:final) { returns(String) }
    attr_reader :key, :lid, :paserk

    sig { params(ikm: String).void }
    def initialize(ikm)
      raise ArgumentError, 'ikm must be 32 bytes' unless ikm.bytesize == 32

      @key = T.let(ikm.freeze, String)
      @paserk = T.let("#{paserk_version}.#{purpose}.#{Util.encode64(key)}".freeze, String)
      @lid = T.let(Operations::ID.lid(self).freeze, String)
    end

    sig { abstract.params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
    def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end # rubocop:disable Naming/MethodParameterName

    sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
    def decrypt(token:, implicit_assertion: ''); end

    sig(:final) do
      override.params(
        payload: T::Hash[String, T.untyped],
        footer: String,
        implicit_assertion: String,
        options: T.nilable(T.any(String, Integer, Symbol, T::Boolean))
      ).returns(String)
    end
    def encode(payload, footer: '', implicit_assertion: '', **options)
      n = T.cast(options.delete(:nonce), T.nilable(String))
      default_claims.merge(payload)
                    .then { |claims| MultiJson.dump(claims, options) }
                    .then { |message| encrypt(message: message, footer: footer, implicit_assertion: implicit_assertion, n: n) }
                    .then(&:to_s)
    end

    sig(:final) do
      override.params(
        payload: String,
        implicit_assertion: String,
        serializer: Interface::Deserializer,
        options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
      ).returns(Result)
    end
    def decode(payload, implicit_assertion: '', serializer: Paseto.config.decode.footer_deserializer, **options)
      token = Token.parse(payload)
      body = decrypt(token: token, implicit_assertion: implicit_assertion)
             .then { |json| MultiJson.load(json, **options) }
      footer = serializer.deserialize(token.footer, options)
      Result.new(body: body, footer: footer)
    end

    sig(:final) { override.returns(String) }
    def id = @lid

    sig(:final) { override.returns(String) }
    def pbkw_header = protocol.pbkd_local_header

    sig(:final) { returns(Interface::PIE) }
    def pie = protocol.pie(self)

    sig(:final) { override.returns(String) }
    def purpose = 'local'

    sig(:final) { override.returns(String) }
    def to_bytes = key

    sig(:final) { params(paserk: String).returns(Interface::Key) }
    def unwrap(paserk) = Paserk.from_paserk(paserk: paserk, wrapping_key: self)

    sig(:final) { params(key: Interface::Key, nonce: T.nilable(String)).returns(String) }
    def wrap(key, nonce: nil) = Paserk.wrap(key: key, wrapping_key: self, nonce: nonce)
  end
end
