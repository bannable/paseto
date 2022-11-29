# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Version
      extend T::Sig
      extend T::Helpers

      include Comparable

      abstract!

      sig { abstract.returns(String) }
      def version; end

      sig { abstract.returns(String) }
      def paserk_version; end

      sig(:final) { params(other: T.untyped).returns(T.nilable(Integer)) }
      def <=>(other)
        case other
        in Interface::Version
          version <=> other.version
        in String
          version <=> other
        else
          nil
        end
      end
    end
  end
end
