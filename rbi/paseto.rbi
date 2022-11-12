# typed: strong
module Paseto
  include Version

  class Error < StandardError
  end

  class ParseError < Error
  end

  class CryptoError < Error
  end

  class InvalidAuthenticator < CryptoError
  end

  class InvalidSignature < CryptoError
  end

  class Key
    extend T::Sig

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

    sig { returns(T::Boolean) }
    def valid?; end
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
  end

  module Version
    VERSION = '0.1.0'
  end

  module Sodium
    module Stream
      class Base
        extend T::Sig
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

        sig { params(ciphertext: String, nonce: String, message: T.nilable(String)).returns(T::Boolean) }
        def do_encrypt(ciphertext, nonce, message); end

        sig { params(message: T.nilable(String)).returns(Integer) }
        def data_len(message); end
      end

      class XChaCha20Xor < Paseto::Sodium::Stream::Base
        extend RbNaCl::Sodium

        sig { params(ciphertext: String, nonce: String, message: T.nilable(String)).returns(T::Boolean) }
        def do_encrypt(ciphertext, nonce, message); end
      end
    end
  end

  module V3
    class Local < Paseto::Key
      SHA384_DIGEST_LEN = 48
      NULL_SALT = T.let(0.chr * SHA384_DIGEST_LEN, String)

      sig { returns(String) }
      attr_reader :key

      sig { returns(Local) }
      def self.generate; end

      sig { params(ikm: String).void }
      def initialize(ikm:); end

      sig do
        params(
          message: String,
          footer: String,
          implicit_assertion: String,
          n: T.nilable(String)
        ).returns(Token)
      end
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end

      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: ''); end

      sig { params(nonce: String).returns([String, String, String]) }
      def calc_keys(nonce); end

      sig { params(payload: String).returns([String, String, String]) }
      def split_payload(payload); end
    end

    class Public < Paseto::Key
      SIGNATURE_BYTE_LEN = 96
      SIGNATURE_PART_LEN = T.let(SIGNATURE_BYTE_LEN / 2, Integer)

      sig { returns(OpenSSL::PKey::EC) }
      attr_reader :key

      sig { returns(Public) }
      def self.generate; end

      sig { params(key: String).void }
      def initialize(key:); end

      sig { params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: ''); end

      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: ''); end

      sig { params(signature: String).returns(String) }
      def rs_to_asn1(signature); end

      sig { params(signature: String).returns(String) }
      def asn1_to_rs(signature); end
    end
  end

  module V4
    class Local < Paseto::Key
      sig { returns(String) }
      attr_reader :key

      sig { returns(Local) }
      def self.generate; end

      sig { params(ikm: String).void }
      def initialize(ikm:); end

      sig do
        params(
          message: String,
          footer: String,
          implicit_assertion: String,
          n: T.nilable(String)
        ).returns(Token)
      end
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end

      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: ''); end

      sig { params(payload: String).returns([String, String, String]) }
      def split_payload(payload); end

      sig { params(nonce: String).returns([String, String, String]) }
      def calc_keys(nonce); end
    end

    class Public < Paseto::Key
      SIGNATURE_BYTES = 64

      sig { returns(T.nilable(RbNaCl::Signatures::Ed25519::SigningKey)) }
      attr_reader :private_key

      sig { returns(RbNaCl::Signatures::Ed25519::VerifyKey) }
      attr_reader :public_key

      sig { returns(Public) }
      def self.generate; end

      sig { params(private_key: T.nilable(String), public_key: T.nilable(String)).void }
      def initialize(private_key: nil, public_key: nil); end

      sig { params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: ''); end

      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: ''); end
    end
  end
end
