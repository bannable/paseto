# typed: strict
# frozen_string_literal: true

module Paseto
  class PaserkTypes < T::Enum
    extend T::Sig

    enums do
      K3LocalWrap = new('k3.local-wrap')
      K3SecretWrap = new('k3.secret-wrap')
    end

    sig { params(input: String).returns(Key) }
    def generate(input)
      case self
      when K3LocalWrap
        V3::Local.new(ikm: input)
      when K3SecretWrap
        V3::Public.new(key: input)
      else
        T.absurd(self)
      end
    end
  end
end
