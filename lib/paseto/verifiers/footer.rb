# typed: strict
# frozen_string_literal: true

module Paseto
  module Verifiers
    class Footer < T::Enum
      extend T::Sig

      enums do
        ForbiddenWPKValue = new
        ForbiddenKIDValue = new
      end

      sig { params(footer: T::Hash[String, T.untyped], options: T::Hash[Symbol, T.untyped]).void }
      def self.verify(footer, options)
        values.each { |v| v.verifier.new(footer, options).verify }
      end

      sig { returns(T.class_of(Validator)) }
      def verifier
        case self
        when ForbiddenWPKValue then Paseto::Validator::WPK
        when ForbiddenKIDValue then Paseto::Validator::KeyID
        else
          T.absurd(self)
        end
      end
    end
  end
end
