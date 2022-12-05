# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module ID
      extend T::Sig
      extend T::Helpers

      interface!

      sig { abstract.params(type: String, paserk: String).returns(String) }
      def encode(type, paserk); end

      sig { abstract.returns(Interface::Version) }
      def protocol; end
    end
  end
end
