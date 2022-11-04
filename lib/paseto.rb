# encoding: binary
# frozen_string_literal: true

require "base64"
require "rbnacl"

require_relative "./rbnacl/stream/base"
require_relative "./rbnacl/stream/xchacha20_xor"

require_relative "paseto/util"
require_relative "paseto/version"
require_relative "paseto/errors"
require_relative "paseto/token"
require_relative "paseto/key"

require_relative "paseto/v4/local"

module Paseto
  include Version
end
