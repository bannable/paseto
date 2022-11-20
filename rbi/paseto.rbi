# typed: strong
module Paseto
  extend Configuration
  VERSION = '0.1.0'

  class Error < StandardError
  end

  class ParseError < Error
  end

  class ValidationError < Error
  end

  class ExpiredToken < ValidationError
  end

  class InactiveToken < ValidationError
  end

  class InvalidIssuer < ValidationError
  end

  class InvalidAudience < ValidationError
  end

  class ImmatureToken < ValidationError
  end

  class InvalidSubject < ValidationError
  end

  class InvalidTokenIdentifier < ValidationError
  end

  class CryptoError < Error
  end

  class InvalidAuthenticator < CryptoError
  end

  class InvalidSignature < CryptoError
  end

  class IncorrectKeyType < CryptoError
  end

  class InvalidKeyPair < CryptoError
  end

  module Configuration
    extend T::Sig

    sig { params(blk: T.proc.params(config: Paseto::Configuration::Box).void).void }
    def configure(&blk); end

    sig { returns(Paseto::Configuration::Box) }
    def config; end
  end

  module Configuration
    class Box
      extend T::Sig

      sig { returns(DecodeConfiguration) }
      attr_accessor :decode

      sig { void }
      def initialize; end

      sig { void }
      def reset!; end
    end
  end

  module Configuration
    class DecodeConfiguration
      extend T::Sig

      sig { returns(T::Boolean) }
      attr_accessor :verify_exp

      sig { returns(T::Boolean) }
      attr_accessor :verify_nbf

      sig { returns(T::Boolean) }
      attr_accessor :verify_iat

      sig { returns(T.any(FalseClass, String)) }
      attr_accessor :verify_sub

      sig { returns(T.any(FalseClass, T::Array[String])) }
      attr_accessor :verify_aud

      sig { returns(T.any(T::Array[T.any(String, Regexp, T.proc.params(issuer: String).returns(T::Boolean))], FalseClass)) }
      attr_accessor :verify_iss

      sig { returns(T.any(
                  T::Boolean,
                  T.proc.params(jti: String).returns(T::Boolean)
                )) }
      attr_accessor :verify_jti

      sig { void }
      def initialize; end

      sig { returns(T::Hash[Symbol, T.untyped]) }
      def to_h; end
    end
  end

  class Key
    abstract!

    extend T::Sig
    extend T::Helpers

    sig { params(version: String, purpose: String).void }
    def initialize(version:, purpose:); end

    sig { returns(String) }
    attr_reader :version

    sig { returns(String) }
    attr_reader :purpose

    sig { returns(String) }
    def header; end

    sig { returns(String) }
    def pae_header; end
  end

  class Token
    include Comparable
    extend T::Sig

    sig { returns(String) }
    attr_reader :version

    sig { returns(String) }
    attr_reader :purpose

    sig { returns(String) }
    attr_reader :payload

    sig { returns(String) }
    attr_reader :footer

    sig { params(str: String).returns(Token) }
    def self.parse(str); end

    sig do
      params(
        payload: String,
        purpose: String,
        version: String,
        footer: String
      ).void
    end
    def initialize(payload:, purpose:, version:, footer: ''); end

    sig { returns(String) }
    def header; end

    sig { returns(String) }
    def to_s; end

    sig { returns(String) }
    def inspect; end

    sig { params(other: T.any(Token, String)).returns(T.nilable(Integer)) }
    def <=>(other); end

    sig { returns(T.class_of(Key)) }
    def type; end

    sig { returns(T::Boolean) }
    def ensure_valid_header; end
  end

  class TokenTypes < T::Enum
    enums do
      V3Local = new('v3.local')
      V3Public = new('v3.public')
      V4Local = new('v4.local')
      V4Public = new('v4.public')
    end

    extend T::Sig

    sig { returns(T.class_of(Key)) }
    def key_klass; end
  end

  module Util
    extend T::Sig

    sig { params(str: String).returns(String) }
    def self.encode64(str); end

    sig { params(str: String).returns(String) }
    def self.decode64(str); end

    sig { params(str: String).returns(String) }
    def self.decode_hex(str); end

    sig { params(num: Integer).returns(String) }
    def self.le64(num); end

    sig { params(parts: String).returns(String) }
    def self.pre_auth_encode(*parts); end

    sig { params(a: String, b: String).returns(T::Boolean) }
    def self.constant_compare(a, b); end

    sig { params(signing_key: RbNaCl::SigningKey).returns(OpenSSL::PKey::PKey) }
    def self.ed25519_pkey_nacl_to_ossl(signing_key); end

    sig do
      params(
        major: Integer,
        minor: Integer,
        fix: Integer,
        patch: Integer
      ).returns(T::Boolean)
    end
    def self.openssl?(major, minor = 0, fix = 0, patch = 0); end
  end

  class Validator
    abstract!

    extend T::Sig
    extend T::Helpers

    sig { returns(T::Hash[T.untyped, T.untyped]) }
    attr_reader :payload

    sig { returns(T::Hash[Symbol, T.untyped]) }
    attr_reader :options

    sig { params(payload: T::Hash[T.untyped, T.untyped], options: T::Hash[Symbol, T.untyped]).void }
    def initialize(payload, options); end

    sig { abstract.void }
    def verify; end

    class Audience < Validator
      sig { override.void }
      def verify; end
    end

    class Expiration < Validator
      sig { override.void }
      def verify; end
    end

    class IssuedAt < Validator
      sig { override.void }
      def verify; end
    end

    class Issuer < Validator
      sig { override.void }
      def verify; end
    end

    class NotBefore < Validator
      sig { override.void }
      def verify; end
    end

    class Subject < Validator
      sig { override.void }
      def verify; end
    end

    class TokenIdentifier < Validator
      sig { override.void }
      def verify; end
    end
  end

  class Verify
    extend T::Sig

    class Verifiers < T::Enum
      enums do
        Audience = new
        IssuedAt = new
        Issuer = new
        Expiration = new
        NotBefore = new
        Subject = new
        TokenIdentifier = new
      end

      extend T::Sig

      sig { returns(T::Array[T.class_of(Validator)]) }
      def self.all; end

      sig { returns(T.class_of(Validator)) }
      def verifier; end
    end

    sig { params(payload: T::Hash[String, T.untyped], options: T::Hash[Symbol, T.untyped]).returns(T::Hash[T.untyped, T.untyped]) }
    def self.verify_claims(payload, options = {}); end

    sig { params(payload: T::Hash[String, T.untyped], options: T::Hash[Symbol, T.untyped]).void }
    def initialize(payload, options); end

    sig { returns(T::Hash[String, T.untyped]) }
    def verify_claims; end
  end

  module Interface
    module Asymmetric
      abstract!

      include Coder
      extend T::Sig
      extend T::Helpers

      sig do
        override.params(
          payload: T::Hash[String, T.untyped],
          footer: String,
          implicit_assertion: String,
          options: T.nilable(T.any(String, Integer, Symbol, T::Boolean))
        ).returns(String)
      end
      def encode(payload:, footer: '', implicit_assertion: '', **options); end

      sig { override.params(payload: String, implicit_assertion: String, options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))).returns(T::Hash[String, T.untyped]) }
      def decode(payload:, implicit_assertion: '', **options); end

      sig { override.params(payload: String, implicit_assertion: String, options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))).returns(T::Hash[String, T.untyped]) }
      def decode!(payload:, implicit_assertion: '', **options); end

      sig { abstract.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: ''); end

      sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: ''); end
    end

    module Coder
      interface!

      extend T::Sig
      extend T::Helpers

      sig do
        abstract.params(
          payload: T::Hash[String, T.untyped],
          footer: String,
          implicit_assertion: String,
          options: T.any(String, Integer, Symbol, T::Boolean)
        ).returns(String)
      end
      def encode(payload:, footer: '', implicit_assertion: '', **options); end

      sig { abstract.params(payload: String, implicit_assertion: String, options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))).returns(T::Hash[String, T.untyped]) }
      def decode(payload:, implicit_assertion: '', **options); end

      sig { abstract.params(payload: String, implicit_assertion: String, options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))).returns(T::Hash[String, T.untyped]) }
      def decode!(payload:, implicit_assertion: '', **options); end
    end

    module Symmetric
      abstract!

      include Coder
      extend T::Sig
      extend T::Helpers

      sig do
        override.params(
          payload: T::Hash[String, T.untyped],
          footer: String,
          implicit_assertion: String,
          options: T.nilable(T.any(String, Integer, Symbol, T::Boolean))
        ).returns(String)
      end
      def encode(payload:, footer: '', implicit_assertion: '', **options); end

      sig { override.params(payload: String, implicit_assertion: String, options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))).returns(T::Hash[String, T.untyped]) }
      def decode(payload:, implicit_assertion: '', **options); end

      sig { override.params(payload: String, implicit_assertion: String, options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))).returns(T::Hash[String, T.untyped]) }
      def decode!(payload:, implicit_assertion: '', **options); end

      sig do
        abstract.params(
          message: String,
          footer: String,
          implicit_assertion: String,
          n: T.nilable(String)
        ).returns(Token)
      end
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end

      sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: ''); end
    end
  end

  module Sodium
    module Stream
      class Base
        abstract!

        extend T::Sig
        extend T::Helpers
        KEYBYTES = 0
        NONCEBYTES = 0
        MESSAGEBYTES_MAX = 0

        sig { returns(Integer) }
        def self.nonce_bytes; end

        sig { returns(Integer) }
        def self.key_bytes; end

        sig { params(key: String).void }
        def initialize(key); end

        sig { params(nonce: String, message: T.nilable(String)).returns(String) }
        def encrypt(nonce, message); end

        sig { returns(Integer) }
        def nonce_bytes; end

        sig { returns(Integer) }
        def key_bytes; end

        sig { returns(String) }
        attr_reader :key

        sig { abstract.params(ciphertext: String, nonce: String, message: T.nilable(String)).returns(T::Boolean) }
        def do_encrypt(ciphertext, nonce, message); end

        sig { params(message: T.nilable(String)).returns(Integer) }
        def data_len(message); end
      end

      class XChaCha20Xor < Paseto::Sodium::Stream::Base
        extend RbNaCl::Sodium

        sig { override.params(ciphertext: String, nonce: String, message: T.nilable(String)).returns(T::Boolean) }
        def do_encrypt(ciphertext, nonce, message); end
      end
    end
  end

  module V3
    class Local < Paseto::Key
      include Interface::Symmetric
      SHA384_DIGEST_LEN = 48
      NULL_SALT = T.let(0.chr * SHA384_DIGEST_LEN, String)

      sig { returns(String) }
      attr_reader :key

      sig { returns(T.attached_class) }
      def self.generate; end

      sig { params(ikm: String).void }
      def initialize(ikm:); end

      sig do
        override.params(
          message: String,
          footer: String,
          implicit_assertion: String,
          n: T.nilable(String)
        ).returns(Token)
      end
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end

      sig { override.params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: ''); end

      sig { params(nonce: String).returns([String, String, String]) }
      def calc_keys(nonce); end

      sig { params(payload: String).returns([String, String, String]) }
      def split_payload(payload); end
    end

    class Public < Paseto::Key
      include Interface::Asymmetric
      SIGNATURE_BYTE_LEN = 96
      SIGNATURE_PART_LEN = T.let(SIGNATURE_BYTE_LEN / 2, Integer)

      sig { returns(OpenSSL::PKey::EC) }
      attr_reader :key

      sig { returns(Public) }
      def self.generate; end

      sig { params(key: String).void }
      def initialize(key:); end

      sig { override.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: ''); end

      sig { override.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: ''); end

      sig { params(signature: String).returns(String) }
      def rs_to_asn1(signature); end

      sig { params(signature: String).returns(String) }
      def asn1_to_rs(signature); end

      sig { returns(T::Boolean) }
      def custom_check_key; end
    end
  end

  module V4
    class Local < Key
      include Interface::Symmetric

      sig { returns(String) }
      attr_reader :key

      sig { returns(T.attached_class) }
      def self.generate; end

      sig { params(ikm: String).void }
      def initialize(ikm:); end

      sig do
        override.params(
          message: String,
          footer: String,
          implicit_assertion: String,
          n: T.nilable(String)
        ).returns(Token)
      end
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end

      sig { override.params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: ''); end

      sig { params(payload: String).returns([String, String, String]) }
      def split_payload(payload); end

      sig { params(nonce: String).returns([String, String, String]) }
      def calc_keys(nonce); end
    end

    class Public < Paseto::Key
      final!

      include Interface::Asymmetric
      SIGNATURE_BYTES = 64

      sig { returns(OpenSSL::PKey::PKey) }
      attr_reader :key

      sig(:final) { returns(Public) }
      def self.generate; end

      sig(:final) { params(key_material: String).void }
      def initialize(key_material); end

      sig(:final) { override.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: ''); end

      sig(:final) { override.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: ''); end
    end
  end
end
