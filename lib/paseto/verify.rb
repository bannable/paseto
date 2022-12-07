# typed: strict
# frozen_string_literal: true

module Paseto
  class Verify
    extend T::Sig

    sig { returns(Result) }
    attr_reader :result

    sig do
      params(
        result: Result,
        options: T::Hash[Symbol, T.untyped]
      ).returns(Verify)
    end
    def self.verify(result, options = {})
      new(result, Paseto.config.decode.to_h.merge(options))
        .then(&:verify_footer)
        .then(&:verify_claims)
    end

    sig do
      params(
        result: Result,
        options: T::Hash[Symbol, T.untyped]
      ).void
    end
    def initialize(result, options)
      @result = result
      @options = options
    end

    sig { returns(T.self_type) }
    def verify_claims
      Verifiers::Payload.verify(@result.body, @options)
      self
    end

    sig { returns(T.self_type) }
    def verify_footer
      footer = @result.footer
      Verifiers::Footer.verify(footer, @options) if footer.is_a?(Hash)
      self
    end
  end
end
