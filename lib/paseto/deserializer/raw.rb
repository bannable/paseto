# typed: strict
# frozen_string_literal: true

module Paseto
  module Deserializer
    module Raw
      extend T::Sig

      extend Interface::Deserializer

      sig(:final) do
        override.params(
          val: String,
          _options: T::Hash[T.untyped, T.untyped]
        ).returns(T.any(String, T::Hash[String, T.untyped]))
      end
      def self.deserialize(val, _options) = val
    end
  end
end
