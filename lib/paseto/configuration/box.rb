# typed: strict
# frozen_string_literal: true

module Paseto
  module Configuration
    class Box
      extend T::Sig

      sig { returns(DecodeConfiguration) }
      attr_accessor :decode

      sig { void }
      def initialize
        @decode = T.let(DecodeConfiguration.new, DecodeConfiguration)
      end

      sig { void }
      def reset!
        @decode = DecodeConfiguration.new
      end
    end
  end
end
