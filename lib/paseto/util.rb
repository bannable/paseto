# typed: strict
# encoding: binary
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

      Base64.urlsafe_decode64(str)
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
      return false unless a.bytesize == b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end
    # rubocop:enable Naming/MethodParameterName
  end
end
