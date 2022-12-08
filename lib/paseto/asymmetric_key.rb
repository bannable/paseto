# typed: strict
# frozen_string_literal: true

module Paseto
  class AsymmetricKey < Interface::Key
    extend T::Sig
    extend T::Helpers

    abstract!

    sig(:final) { override.returns(String) }
    attr_reader :id, :paserk

    sig(:final) { returns(String) }
    attr_reader :pid, :public_paserk

    sig { params(_key: T.untyped).void }
    def initialize(_key)
      @public_paserk = T.let("#{paserk_version}.public.#{Util.encode64(public_bytes)}".freeze, String)

      @pid = T.let(Operations::ID.pid(self).freeze, String)

      if private?
        @paserk = T.let("#{paserk_version}.secret.#{Util.encode64(to_bytes)}".freeze, String)
        @id = T.let(Operations::ID.sid(self).freeze, String)
      else
        @paserk = @public_paserk
        @id = T.let(@pid, String)
      end
    end

    sig { abstract.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
    def sign(message:, footer: '', implicit_assertion: ''); end

    sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
    def verify(token:, implicit_assertion: ''); end

    sig { abstract.returns(String) }
    def public_to_pem; end

    sig { abstract.returns(String) }
    def private_to_pem; end

    sig { abstract.returns(T::Boolean) }
    def private?; end

    sig { abstract.returns(String) }
    def public_bytes; end

    sig { abstract.params(other: T.untyped).returns(String) }
    def ecdh(other); end

    sig(:final) do
      override.params(
        payload: T::Hash[String, T.untyped],
        footer: String,
        implicit_assertion: String,
        options: T.nilable(T.any(String, Integer, Symbol, T::Boolean))
      ).returns(String)
    end
    def encode!(payload, footer: '', implicit_assertion: '', **options)
      MultiJson.dump(payload, options)
               .then { |json| sign(message: json, footer: footer, implicit_assertion: implicit_assertion) }
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
    def decode!(payload, implicit_assertion: '', serializer: Paseto.config.decode.footer_deserializer, **options)
      token = Token.parse(payload)
      claims = verify(token: token, implicit_assertion: implicit_assertion)
             .then { |json| MultiJson.load(json, **options) }
      footer = serializer.deserialize(token.footer, options)
      Result.new(claims: claims, footer: footer)
    end

    sig(:final) { override.returns(String) }
    def pbkw_header = protocol.pbkd_secret_header

    sig(:final) { override.returns(String) }
    def purpose = 'public'

    sig(:final) { returns(Interface::PKE) }
    def pke = protocol.pke(self)

    sig(:final) { returns(String) }
    def sid = @sid ||= T.let(Operations::ID.sid(self), T.nilable(String))

    sig(:final) { params(other: SymmetricKey).returns(String) }
    def seal(other) = Paserk.seal(sealing_key: self, key: other)

    sig(:final) { params(paserk: String).returns(SymmetricKey) }
    def unseal(paserk) = Paserk.from_paserk(paserk: paserk, unsealing_key: self)
  end
end
