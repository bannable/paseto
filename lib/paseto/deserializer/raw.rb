# typed: strict
# frozen_string_literal: true

module Paseto
  module Deserializer
    module Raw
      extend T::Sig

      extend Interface::Deserializer

      sig(:final) { override.params(val: String).returns(String) }
      def self.deserialize(val) = val
    end
  end
end
