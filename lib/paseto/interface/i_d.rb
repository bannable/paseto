# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module ID
      extend T::Sig
      extend T::Helpers

      abstract!

      sig(:final) { params(type: String, paserk: String).returns(String) }
      def encode(type, paserk)
        header = "#{protocol.paserk_version}.#{type}."
        d = protocol.digest("#{header}#{paserk}", digest_size: 33)
        "#{header}#{Util.encode64(d)}"
      end

      sig { abstract.returns(Interface::Version) }
      def protocol; end
    end
  end
end
