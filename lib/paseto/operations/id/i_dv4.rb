# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class ID
      module IDv4
        extend T::Sig

        extend Interface::ID

        sig { override.returns(Protocol::Version4) }
        def self.protocol
          Protocol::Version4.new
        end
      end
    end
  end
end
