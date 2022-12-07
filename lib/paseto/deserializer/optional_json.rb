# typed: strict
# frozen_string_literal: true

module Paseto
  module Deserializer
    module OptionalJson
      extend T::Sig

      extend Interface::Deserializer

      sig(:final) { override.params(val: String).returns(T.any(String, T::Hash[String, T.untyped])) }
      def self.deserialize(val)
        MultiJson.load(val)
      rescue MultiJson::ParseError
        val
      end
    end
  end
end
