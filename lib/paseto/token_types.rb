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

    sig { returns(T.class_of(Key)) }
    def key_klass
      case self
      when V3Local then V3::Local
      when V3Public then V3::Public
      when V4Local then V4::Local
      when V4Public then V4::Public
      else
        T.absurd(self)
      end
    end
  end
end
