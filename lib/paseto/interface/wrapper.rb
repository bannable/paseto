# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Wrapper
      extend T::Sig
      extend T::Helpers

      interface!

      sig { abstract.params(key: Key, nonce: T.nilable(String)).returns(String) }
      def encode(key, nonce: nil); end

      sig { abstract.params(paserk: [String, String, String, String]).returns(Key) }
      def decode(paserk); end
    end
  end
end
