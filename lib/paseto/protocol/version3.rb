# typed: strict
# frozen_string_literal: true

module Paseto
  module Protocol
    class Version3
      extend T::Sig
      extend T::Helpers

      include Interface::Version

      sig(:final) { override.returns(String) }
      def self.paserk_version
        'k3'
      end

      sig(:final) { override.returns(String) }
      def self.pbkd_local_header
        'k3.local-pw'
      end

      sig(:final) { override.returns(String) }
      def self.pbkd_secret_header
        'k3.secret-pw'
      end

      sig(:final) { override.returns(String) }
      def self.version
        'v3'
      end
    end
  end
end
