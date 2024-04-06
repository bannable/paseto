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
      raise ArgumentError, 'num must not be signed' if num.negative?

      [num].pack('Q<')
    end

    sig { params(num: Integer).returns(String) }
    def self.int_to_be32(num)
      raise ArgumentError, 'num too large' if num.bit_length > 32
      raise ArgumentError, 'num must not be signed' if num.negative?

      [num].pack('N')
    end

    sig { params(num: Integer).returns(String) }
    def self.int_to_be64(num)
      raise ArgumentError, 'num too large' if num.bit_length > 64
      raise ArgumentError, 'num must not be signed' if num.negative?

      [num].pack('Q>')
    end

    sig { params(val: String).returns(Integer) }
    def self.be64_to_int(val)
      raise ArgumentError, 'input size incorrect' unless val.bytesize == 8

      val.unpack1('Q>')
    end

    sig { params(val: String).returns(Integer) }
    def self.be32_to_int(val)
      raise ArgumentError, 'input size incorrect' unless val.bytesize == 4

      val.unpack1('N')
    end

    sig { params(parts: String).returns(String) }
    def self.pre_auth_encode(*parts)
      parts.inject(le64(parts.size)) do |memo, part|
        "#{memo}#{le64(part.bytesize)}#{part}"
      end
    end

    # rubocop:disable Naming/MethodParameterName, Style/IdenticalConditionalBranches
    # Moving the sig out of the conditional triggers a bug in rubocop-sorbet

    # Use a faster comparison when RbNaCl is available
    if Paseto::HAS_RBNACL
      sig { params(a: String, b: String).returns(T::Boolean) }
      def self.constant_compare(a, b)
        h_a = RbNaCl::Hash.blake2b(a)
        h_b = RbNaCl::Hash.blake2b(b)
        RbNaCl::Util.verify64(h_a, h_b)
      end
    else
      sig { params(a: String, b: String).returns(T::Boolean) }
      def self.constant_compare(a, b)
        OpenSSL.secure_compare(a, b)
      end
    end

    # rubocop:enable Naming/MethodParameterName, Style/IdenticalConditionalBranches

    # Check if the libcrypto version that's running is actually openssl, and that the version
    # is at least the provided major/minor/fix/patch level.
    sig { params(major: Integer, minor: Integer, fix: Integer, patch: Integer).returns(T::Boolean) }
    def self.openssl?(major, minor = 0, fix = 0, patch = 0)
      return false if OpenSSL::OPENSSL_VERSION.include?('LibreSSL')

      (major * 0x10000000) + (minor * 0x100000) + (fix * 0x1000) + (patch * 0x10) <= OpenSSL::OPENSSL_VERSION_NUMBER
    end
  end
end
