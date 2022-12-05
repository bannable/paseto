# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class ID
      module IDv3
        extend T::Sig

        extend Interface::ID

        sig { override.params(type: String, paserk: String).returns(String) }
        def self.encode(type, paserk)
          header = "k3.#{type}."
          d = protocol.digest("#{header}#{paserk}", digest_size: 33)
          "#{header}#{Util.encode64(d)}"
        end

        sig { override.returns(Protocol::Version3) }
        def self.protocol
          Protocol::Version3.new
        end
      end
    end
  end
end
