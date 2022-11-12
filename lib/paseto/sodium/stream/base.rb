# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Sodium
    module Stream
      # Abstract base class for Stream ciphers
      class Base
        extend T::Sig

        # Number of bytes in a valid key
        KEYBYTES = 0

        # Number of bytes in a valid nonce
        NONCEBYTES = 0

        MESSAGEBYTES_MAX = 0

        sig { returns(Integer) }
        def self.nonce_bytes
          const_get(:NONCEBYTES)
        end

        sig { returns(Integer) }
        def self.key_bytes
          const_get(:KEYBYTES)
        end

        # Create a new Stream.
        #
        # Sets up Stream with a secret key for encrypting and decrypting messages.
        #
        # @param key [String] The key to encrypt and decrypt with
        #
        # @raise [RbNaCl::LengthError] on invalid keys
        #
        # @return [RbNaCL::Stream::Base] The new Stream construct, ready to use
        sig { params(key: String).void }
        def initialize(key)
          @key = T.let(RbNaCl::Util.check_string(key, key_bytes, 'Secret key'), String)
        end

        sig { params(nonce: String, message: T.nilable(String)).returns(String) }
        def encrypt(nonce, message)
          RbNaCl::Util.check_length(nonce, nonce_bytes, 'Nonce')

          ciphertext = RbNaCl::Util.zeros(data_len(message))

          success = do_encrypt(ciphertext, nonce, message)
          raise CryptoError, 'Encryption failed' unless success

          ciphertext
        end

        sig { returns(Integer) }
        def nonce_bytes
          self.class.nonce_bytes
        end

        sig { returns(Integer) }
        def key_bytes
          self.class.key_bytes
        end

        private

        # Symmetric encryption key for a cipher instance
        sig { returns(String) }
        attr_reader :key

        sig { params(ciphertext: String, nonce: String, message: T.nilable(String)).returns(T::Boolean) }
        def do_encrypt(ciphertext, nonce, message)
          raise NotImplementedError
        end

        sig { params(message: T.nilable(String)).returns(Integer) }
        def data_len(message)
          return 0 unless message

          message.bytesize
        end
      end
    end
  end
end
