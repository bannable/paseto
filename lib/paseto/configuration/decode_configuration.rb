# typed: strict
# frozen_string_literal: true

module Paseto
  module Configuration
    class DecodeConfiguration
      extend T::Sig

      sig { void }
      def initialize
      end

      sig { returns(T::Hash[T.untyped, T.untyped]) }
      def to_h
        {
        }
      end
    end
  end
end
