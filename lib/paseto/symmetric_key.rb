module Paseto
  class SymmetricKey
    HEADER = 'v4.local'

    # @dynamic ikm, version
    attr_reader :ikm
    attr_reader :version

    def initialize(ikm:, version:)
      @ikm = ikm
      @version = version
    end

    def valid_for?(version:, purpose:)
      # https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md step 1
      return false if purpose != 'local'
      return false if version != @version
      true
    end
  end
end