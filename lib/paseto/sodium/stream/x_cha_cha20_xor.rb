# encoding: binary
# typed: false
# frozen_string_literal: true

module Paseto
  module Sodium
    module Stream
      class XChaCha20Xor < Paseto::Sodium::Stream::Base
        extend RbNaCl::Sodium
        sodium_type :stream

        sodium_primitive :xchacha20

        sodium_constant :KEYBYTES
        sodium_constant :NONCEBYTES
        sodium_constant :MESSAGEBYTES_MAX

        sodium_function :stream_xchacha20_xor,
                        :crypto_stream_xchacha20_xor,
                        %i[pointer pointer ulong_long pointer pointer]

        private

        sig { params(ciphertext: String, nonce: String, message: T.nilable(String)).returns(T::Boolean) }
        def do_encrypt(ciphertext, nonce, message)
          self.class.stream_xchacha20_xor(ciphertext, message, data_len(message), nonce, @key)
        end
      end
    end
  end
end
