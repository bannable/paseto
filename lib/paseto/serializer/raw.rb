# typed: strict
# frozen_string_literal: true

module Paseto
  module Serializer
    module Raw
      extend T::Sig

      extend Interface::Serializer

      sig(:final) do
        override.params(
          val: String,
          _options: T::Hash[T.untyped, T.untyped]
        ).returns(T.any(String, T::Hash[String, T.untyped]))
      end
      def self.deserialize(val, _options) = val

      sig(:final) { override.params(val: T.untyped, _options: T.untyped).returns(String) }
      def self.serialize(val, _options) = val
    end
  end
end
