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

    # Encrypts and authenticates `message` with optional binding input `implicit_assertion`, returning a `Token`.
    # If `footer` is provided, it is included as authenticated data in the reuslting `Token``.
    # `n` must not be used outside of tests.
    sig(:final) { params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
    def encrypt(message:, footer: '', implicit_assertion: '', n: nil) # rubocop:disable Naming/MethodParameterName
      n ||= SecureRandom.random_bytes(32)

      ek, n2, ak = calc_keys(n)

      c = protocol.crypt(payload: message, key: ek, nonce: n2)

      Util.pre_auth_encode(pae_header, n, c, footer, implicit_assertion)
          .then { |pre_auth| protocol.hmac(pre_auth, key: ak) }
          .then { |t| "#{n}#{c}#{t}" }
          .then { |payload| Token.new(payload: payload, version: version, purpose: purpose, footer: footer) }
    end

    # Verify and decrypt an encrypted Token, with an optional string `implicit_assertion`, and return the plaintext.
    # If `token` includes a footer, it is treated as authenticated data to be verified but not returned.
    # `token` must be a `v4.local` type Token.
    sig(:final) { params(token: Token, implicit_assertion: String).returns(String) }
    def decrypt(token:, implicit_assertion: '')
      raise LucidityError unless header == token.header

      n, c, t = split_payload(token.raw_payload)

      ek, n2, ak = calc_keys(n)

      pre_auth = Util.pre_auth_encode(pae_header, n, c, token.raw_footer, implicit_assertion)
      t2 = protocol.hmac(pre_auth, key: ak)
      raise InvalidAuthenticator unless Util.constant_compare(t, t2)

      protocol.crypt(payload: c, key: ek, nonce: n2).encode(Encoding::UTF_8)
    rescue Encoding::UndefinedConversionError
      raise ParseError, 'invalid payload encoding'
    end

    sig(:final) do
      override.params(
        payload: T::Hash[String, T.untyped],
        footer: String,
        implicit_assertion: String,
        options: T.nilable(T.any(String, Integer, Symbol, T::Boolean))
      ).returns(String)
    end
    def encode!(payload, footer: '', implicit_assertion: '', **options)
      n = T.cast(options.delete(:nonce), T.nilable(String))
      MultiJson.dump(payload, options)
               .then { |message| encrypt(message: message, footer: footer, implicit_assertion: implicit_assertion, n: n) }
               .then(&:to_s)
    end

    sig(:final) do
      override.params(
        payload: String,
        implicit_assertion: String,
        options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
      ).returns(Result)
    end
    def decode!(payload, implicit_assertion: '', **options)
      token = Token.parse(payload)

      decrypt(token: token, implicit_assertion: implicit_assertion)
        .then { |json| MultiJson.load(json, **options) }
        .then { |claims| Result.new(claims: claims, footer: token.footer) }
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

    private

    sig { abstract.params(nonce: String).returns([String, String, String]) }
    def calc_keys(nonce); end

    sig { abstract.params(payload: String).returns([String, String, String]) }
    def split_payload(payload); end
  end
end
