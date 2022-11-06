# encoding: binary
# frozen_string_literal: true

module Paseto
  module Sodium
    module Stream
      class XChaCha20Xor < Paseto::Sodium::Stream::Base
        extend RbNaCl::Sodium
        if RbNaCl::Sodium::Version.supported_version?("1.0.12")
          sodium_type :stream

          sodium_primitive :xchacha20

          sodium_constant :KEYBYTES
          sodium_constant :NONCEBYTES
          sodium_constant :MESSAGEBYTES_MAX

          sodium_function :stream_xchacha20_xor,
                          :crypto_stream_xchacha20_xor,
                          %i[pointer pointer ulong_long pointer pointer]
          
          private

          def do_encrypt(ciphertext, nonce, message)
            self.class.stream_xchacha20_xor(ciphertext, message, message.bytesize, nonce, @key)
          end
        end
      end
    end
  end
end
