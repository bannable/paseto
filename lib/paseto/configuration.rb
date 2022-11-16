# typed: strict
# frozen_string_literal: true

module Paseto
  module Configuration
    extend T::Sig

    sig { params(blk: T.proc.params(config: Paseto::Configuration::Box).void).void }
    def configure(&blk) # rubocop:disable Naming/BlockForwarding, Lint/UnusedMethodArgument
      yield(config)
    end

    sig { returns(Paseto::Configuration::Box) }
    def config
      @config ||= T.let(Configuration::Box.new, T.nilable(Paseto::Configuration::Box))
    end
  end
end
