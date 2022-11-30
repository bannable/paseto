# typed: strict
# frozen_string_literal: true

module Paseto
  class Versions < T::Enum
    extend T::Sig

    enums do
      V3Version = new(Protocol::Version3)
      V4Version = new(Protocol::Version4)
      V3Str = new('v3')
      V4Str = new('v4')
      K3Str = new('k3')
      K4Str = new('k4')
    end

    sig { returns(Interface::Version) }
    def instance
      case self
      when V3Version, V3Str, K3Str then Protocol::Version3.new
      when V4Version, V4Str, K4Str then Protocol::Version4.new
      end
    end
  end
end
