# encoding: binary
# frozen_string_literal: true

require "base64"
require "rbnacl"

require_relative "./rbnacl/stream/base"
require_relative "./rbnacl/stream/xchacha20_xor"

require_relative "paseto/version"
require_relative "paseto/errors"
require_relative "paseto/token"
require_relative "paseto/key"

require_relative "paseto/v4/local"

module Paseto
  include Version

  def self.encode64(str)
    Base64.urlsafe_encode64(str).tr("=", "")
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
end
