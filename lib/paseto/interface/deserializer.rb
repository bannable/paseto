# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Deserializer
      extend T::Sig
      extend T::Helpers

      interface!

      sig { abstract.params(val: String).returns(T.untyped) }
      def deserialize(val); end
    end
  end
end
