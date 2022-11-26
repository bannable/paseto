# typed: strict
# frozen_string_literal: true

module Paseto
  module V4
    module Version
      extend T::Sig
      extend T::Helpers

      include Interface::Version

      abstract!

      sig(:final) { override.returns(String) }
      def version
        'v4'
      end

      sig(:final) { override.returns(String) }
      def paserk_version
        'k4'
      end
    end
  end
end
