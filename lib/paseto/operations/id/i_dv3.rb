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
          d = T.must(OpenSSL::Digest.digest('SHA384', "#{header}#{paserk}")[0, 33])
          "#{header}#{Util.encode64(d)}"
        end
      end
    end
  end
end
