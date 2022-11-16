# encoding: binary
# typed: strict
# frozen_string_literal: true

require 'base64'
require 'multi_json'
require 'openssl'
require 'rbnacl'
require 'securerandom'
require 'sorbet-runtime'
require 'time'

require 'paseto/version'
require 'paseto/errors'
require 'paseto/sodium'
require 'paseto/util'
require 'paseto/token'
require 'paseto/configuration'
require 'paseto/key'
require 'paseto/interface'

require 'paseto/v3'
require 'paseto/v4'

module Paseto
  extend T::Sig
  extend Configuration

  include Version
end
