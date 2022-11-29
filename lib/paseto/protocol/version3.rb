# typed: strict
# frozen_string_literal: true

module Paseto
  module Protocol
    class Version3
      extend T::Sig
      extend T::Helpers

      include Interface::Version

      sig(:final) { override.returns(String) }
      def version
        'v3'
      end

      sig(:final) { override.returns(String) }
      def paserk_version
        'k3'
      end
    end
  end
end
