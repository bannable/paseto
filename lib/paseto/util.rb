# encoding: binary
# frozen_string_literal: true

module Paseto
  module Util
    def self.encode64(str)
      Base64.urlsafe_encode64(str, padding: false)
    end

    def self.decode64(str)
      Base64.urlsafe_decode64(str)
    end

    def self.encode_hex(str)
      str.unpack1('H*')
    end

    def self.decode_hex(str)
      [str].pack('H*')
    end

    def self.le64(num)
      [num].pack('Q<')
    end

    def self.pre_auth_encode(*parts)
      parts.inject(le64(parts.size)) do |memo, part|
        memo + le64(part.bytesize) + part
      end
    end

    def self.constant_compare(a, b)
      return false unless a.bytesize == b.bytesize
      b_bytes = b.bytes
      res = 0
      a.each_byte { |byte| res |= byte ^ b_bytes.shift.to_i }
      res == 0
    end
  end
end
