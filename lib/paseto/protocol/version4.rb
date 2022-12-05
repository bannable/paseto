# typed: strict
# frozen_string_literal: true

module Paseto
  module Protocol
    class Version4
      extend T::Sig
      extend T::Helpers

      include Interface::Version

      sig(:final) { override.returns(String) }
      def self.paserk_version
        'k4'
      end

      sig(:final) { override.returns(String) }
      def self.pbkd_local_header
        'k4.local-pw'
      end

      sig(:final) { override.returns(String) }
      def self.pbkd_secret_header
        'k4.secret-pw'
      end

      sig(:final) { override.returns(String) }
      def self.version
        'v4'
      end
    end
  end
end
