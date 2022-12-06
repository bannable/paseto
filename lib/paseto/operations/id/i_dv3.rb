# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class ID
      module IDv3
        extend T::Sig

        extend Interface::ID

        sig { override.returns(Protocol::Version3) }
        def self.protocol
          Protocol::Version3.new
        end
      end
    end
  end
end
