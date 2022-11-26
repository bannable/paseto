# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Util
    extend T::Sig

    sig { params(str: String).returns(String) }
    def self.encode64(str)
      Base64.urlsafe_encode64(str, padding: false)
    end

    sig { params(str: String).returns(String) }
    def self.decode64(str)
      # Ruby's Base64 library does not care about whether or not padding is present,
      # but the PASETO test vectors do.
      return '' if str.include?('=')

      Base64.urlsafe_decode64(str).b
    rescue ArgumentError
      ''
    end

    sig { params(str: String).returns(String) }
    def self.decode_hex(str)
      [str].pack('H*')
    end

    sig { params(num: Integer).returns(String) }
    def self.le64(num)
      raise ArgumentError, 'num too large' if num.bit_length > 64
      raise ArgumentError, 'num must not be negative' unless num == num.abs

      [num].pack('Q<')
    end

    sig { params(parts: String).returns(String) }
    def self.pre_auth_encode(*parts)
      parts.inject(le64(parts.size)) do |memo, part|
        memo + le64(part.bytesize) + part
      end
    end

    # rubocop:disable Naming/MethodParameterName
    sig { params(a: String, b: String).returns(T::Boolean) }
    def self.constant_compare(a, b)
      OpenSSL.secure_compare(a, b)
    end
    # rubocop:enable Naming/MethodParameterName

    # Check if the libcrypto version that's running is actually openssl, and that the version
    # is at least the provided major/minor/fix/patch level.
    sig { params(major: Integer, minor: Integer, fix: Integer, patch: Integer).returns(T::Boolean) }
    def self.openssl?(major, minor = 0, fix = 0, patch = 0)
      return false if OpenSSL::OPENSSL_VERSION.include?('LibreSSL')

      OpenSSL::OPENSSL_VERSION_NUMBER >=
        (major * 0x10000000) + (minor * 0x100000) + (fix * 0x1000) + (patch * 0x10)
    end
  end
end
