# encoding: binary
# frozen_string_literal: true

module Paseto
  module Sodium
    module Stream
      # Abstract base class for Stream ciphers
      class Base
        # Number of bytes in a valid key
        KEYBYTES = 0

        # Number of bytes in a valid nonce
        NONCEBYTES = 0

        MESSAGEBYTES_MAX = 0

        def self.nonce_bytes
          const_get(:NONCEBYTES)
        end

        def self.key_bytes
          const_get(:KEYBYTES)
        end

        def self.primitive
          raise NotImplementedError
        end

        # Create a new Stream.
        #
        # Sets up Stream with a secret key for encrypting and decrypting messages.
        #
        # @paramn key [String] The key to encrypt and decrypt with
        #
        # @raise [RbNaCl::LengthError] on invalid keys
        #
        # @return [RbNaCL::Stream::Base] The new Stream construct, ready to use
        def initialize(key)
          @key = RbNaCl::Util.check_string(key, key_bytes, "Secret key")
        end

        def encrypt(nonce, message)
          RbNaCl::Util.check_length(nonce, nonce_bytes, "Nonce")

          ciphertext = RbNaCl::Util.zeros(data_len(message))

          success = do_encrypt(ciphertext, nonce, message)
          raise CryptoError, "Encryption failed" unless success

          ciphertext
        end

        def primitive
          self.class.primitive
        end

        def nonce_bytes
          self.class.nonce_bytes
        end

        def key_bytes
          self.class.key_bytes
        end

        private

        # @dynamic key

        # Symmetric encryption key for a cipher instance
        attr_reader :key

        def do_encrypt(_ciphertext, _nonce, _message)
          raise NotImplementedError
        end

        def data_len(data)
          return 0 unless data

          data.bytesize
        end
      end
    end
  end
end
