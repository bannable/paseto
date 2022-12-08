# typed: strict
# frozen_string_literal: true

module Paseto
  class AsymmetricKey < Interface::Key
    extend T::Sig
    extend T::Helpers

    abstract!

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
    def encode(payload, footer: '', implicit_assertion: '', **options)
      message = MultiJson.dump(payload, options)
      sign(message: message, footer: footer, implicit_assertion: implicit_assertion).to_s
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
      body = verify(token: token, implicit_assertion: implicit_assertion)
             .then { |plain| MultiJson.load(plain, **options) }
      footer = serializer.deserialize(token.footer, options)
      Result.new(body: body, footer: footer)
    end

    sig(:final) { override.returns(String) }
    def pbkw_header
      protocol.pbkd_secret_header
    end

    sig(:final) { returns(Interface::PKE) }
    def pke
      protocol.pke(self)
    end

    sig(:final) { override.returns(String) }
    def purpose
      'public'
    end

    sig(:final) { override.returns(String) }
    def to_paserk
      return to_public_paserk unless private?

      "#{paserk_version}.secret.#{Util.encode64(to_bytes)}"
    end

    sig(:final) { returns(String) }
    def to_public_paserk
      "#{paserk_version}.public.#{Util.encode64(public_bytes)}"
    end

    sig(:final) { returns(String) }
    def id
      return sid if private?

      pid
    end

    sig(:final) { returns(String) }
    def pid
      Operations::ID.pid(self)
    end

    sig(:final) { returns(String) }
    def sid
      Operations::ID.sid(self)
    end

    sig(:final) { params(other: SymmetricKey).returns(String) }
    def seal(other)
      Paserk.seal(sealing_key: self, key: other)
    end

    sig(:final) { params(paserk: String).returns(SymmetricKey) }
    def unseal(paserk)
      Paserk.from_paserk(paserk: paserk, unsealing_key: self)
    end
  end
end
