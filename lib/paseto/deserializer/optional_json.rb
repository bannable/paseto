# typed: strict
# frozen_string_literal: true

module Paseto
  module Deserializer
    module OptionalJson
      extend T::Sig

      extend Interface::Deserializer

      sig(:final) do
        override.params(
          val: String,
          options: T::Hash[T.untyped, T.untyped]
        ).returns(T.any(String, T::Hash[String, T.untyped]))
      end
      def self.deserialize(val, options = {})
        MultiJson.load(val)
      rescue MultiJson::ParseError
        val
      end
    end
  end
end
