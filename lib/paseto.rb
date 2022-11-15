# encoding: binary
# typed: strict
# frozen_string_literal: true

require 'base64'
require 'multi_json'
require 'openssl'
require 'rbnacl'
require 'securerandom'
require 'sorbet-runtime'

require_relative 'paseto/errors'
require_relative 'paseto/sodium/stream/base'
require_relative 'paseto/sodium/stream/x_cha_cha20_xor'

require_relative 'paseto/util'
require_relative 'paseto/version'
require_relative 'paseto/token'
require_relative 'paseto/token_validator'

require_relative 'paseto/key'
require_relative 'paseto/i_coder'
require_relative 'paseto/i_symmetric'
require_relative 'paseto/i_asymmetric'
require_relative 'paseto/v3/local'
require_relative 'paseto/v3/public'
require_relative 'paseto/v4/local'
require_relative 'paseto/v4/public'

module Paseto
  extend T::Sig
  extend Configuration

  include Version
end
