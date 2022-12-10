# typed: strict
# frozen_string_literal: true

module Paseto
  module Serializer
    module OptionalJson
      extend T::Sig

      extend Interface::Serializer

      sig { override.params(val: String, options: T::Hash[T.untyped, T.untyped]).returns(T.untyped) }
      def self.deserialize(val, options)
        obj = MultiJson.load(val, options)
        case obj
        when Hash then obj
        else val
        end
      rescue MultiJson::ParseError
        val
      end

      sig { override.params(val: T.untyped, options: T::Hash[T.untyped, T.untyped]).returns(String) }
      def self.serialize(val, options)
        return val unless val.is_a?(Hash)

        MultiJson.dump(val, options)
      end
    end
  end
end
