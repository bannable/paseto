# frozen_string_literal: true

require "base64"
require "rbnacl"

require_relative "paseto/version"
require_relative "paseto/errors"
require_relative "paseto/versions"
require_relative "paseto/key/symmetric"
require_relative "paseto/key/asymmetric_public"
require_relative "paseto/key/asymmetric_secret"
require_relative "paseto/v4"

module Paseto
  def self.encode64(str)
    Base64.urlsafe_encode64(str).tr("=", "")
  end

  def self.decode64(str)
    Base64.urlsafe_decode64(str)
  end
end
