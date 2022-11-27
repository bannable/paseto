# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Version
      extend T::Sig
      extend T::Helpers

      requires_ancestor { Paseto::Key }

      interface!

      sig { abstract.returns(String) }
      def version; end

      sig { abstract.returns(String) }
      def paserk_version; end
    end
  end
end
