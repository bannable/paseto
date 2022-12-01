# typed: strict
# frozen_string_literal: true

module Paseto
  class TokenTypes < T::Enum
    extend T::Sig

    enums do
      V3Local = new('v3.local')
      V3Public = new('v3.public')
      V4Local = new('v4.local')
      V4Public = new('v4.public')
    end

    sig { returns(T.nilable(T.class_of(Interface::Key))) }
    def key_klass
      case self
      in V3Local then V3::Local
      in V3Public then V3::Public
      in V4Local if Paseto.rbnacl?
        V4::Local
      in V4Public if Paseto.rbnacl?
        V4::Public
      else
        nil
      end
    end
  end
end
