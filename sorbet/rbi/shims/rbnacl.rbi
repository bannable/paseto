# typed: false

module RbNaCl
  module Hash
    sig do
      params(
        data: String,
        key: T.nilable(String),
        digest_size: T.nilable(Integer),
        salt: T.nilable(String)
      ).returns(String)
    end
    def self.blake2b(data, key: nil, digest_size: nil, salt: nil); end
  end

  module Util
    class << self
      sig { params(string: String, length: Integer, description: String).returns(String) }
      def check_string(string, length, description); end

      sig { params(length: Integer).returns(String) }
      def zeroes(length); end
    end
  end
end
