# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Serializer
      extend T::Sig
      extend T::Helpers

      interface!

      sig { abstract.params(val: String, options: T::Hash[T.untyped, T.untyped]).returns(T.untyped) }
      def deserialize(val, options); end

      sig { abstract.params(val: T.untyped, options: T::Hash[T.untyped, T.untyped]).returns(String) }
      def serialize(val, options); end
    end
  end
end
