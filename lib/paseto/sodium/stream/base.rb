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

          ciphertext = RbNaCl::Util.zeros(message.bytesize)

          success = do_encrypt(ciphertext, nonce, message)
          raise CryptoError, "Encryption failed" unless success

          ciphertext
        end

        def self.primitive
          raise NotImplementedError
        end

        def primitive
          self.class.primitive
        end

        def self.nonce_bytes
          self.const_get(:NONCEBYTES)
        end

        def nonce_bytes
          self.class.nonce_bytes
        end

        def self.key_bytes
          self.const_get(:KEYBYTES)
        end

        def key_bytes
          self.class.key_bytes
        end

        private
        
        def key
          @key
        end

        def do_encrypt(_ciphertext, _nonce, _message)
          raise NotImplementedError
        end
      end
    end
  end
end
