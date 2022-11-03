# encoding: binary
# frozen_string_literal: true

module RbNaCl
  module Stream
    class XChaCha20Xor < RbNaCl::Stream::Base
      extend Sodium
      if Sodium::Version.supported_version?("1.0.12")
        sodium_type :stream

        sodium_primitive :xchacha20

        sodium_constant :KEYBYTES
        sodium_constant :NONCEBYTES

        sodium_function :stream_xchacha20_xor,
                        :crypto_stream_xchacha20_xor,
                        %i[pointer pointer ulong_long pointer pointer]
        
        private

        def do_encrypt(ciphertext, nonce, message)
          self.class.stream_xchacha20_xor(ciphertext, message, data_len(message), nonce, @key)
        end

        def do_decrypt(message, nonce, ciphertext)
          self.class.stream_xchacha20_xor(message, ciphertext, data_len(ciphertext), nonce, @key)
        end
      end
    end
  end
end