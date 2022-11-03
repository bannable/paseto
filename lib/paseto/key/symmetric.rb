# frozen_string_literal: true

module Paseto
  module Key
    class Symmetric
      # @dynamic material, version
      attr_reader :material
      attr_reader :version

      def initialize(ikm:, version:)
        @material = ikm
        @version = version
      end

      def valid_for?(version:, purpose:)
        # https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md step 1
        purpose == "local" && version == @version
      end
    end
  end
end
