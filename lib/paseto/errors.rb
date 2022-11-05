# frozen_string_literal: true

module Paseto
  class Error < StandardError; end
  class ParseError < Error; end
  class DecryptError < Error; end
end
