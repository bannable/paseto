# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class ID
      extend T::Sig

      sig { params(paserk: String).returns(String) }
      def encode(paserk)

      end
    end
  end
end
