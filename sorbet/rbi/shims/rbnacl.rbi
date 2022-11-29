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

  module PasswordHash
    sig do
      params(
        password: String,
        salt: String,
        opslimit: T.any(Symbol, Integer),
        memlimit: T.any(Symbol, Integer),
        digest_size: Integer
      ).returns(String)
    end
    def self.argon2(password, salt, opslimit, memlimit, digest_size = 64); end

    sig do
      params(
        password: String,
        salt: String,
        opslimit: T.any(Symbol, Integer),
        memlimit: T.any(Symbol, Integer),
        digest_size: Integer
      ).returns(String)
    end
    def self.argon2i(password, salt, opslimit, memlimit, digest_size = 64); end

    sig do
      params(
        password: String,
        salt: String,
        opslimit: T.any(Symbol, Integer),
        memlimit: T.any(Symbol, Integer),
        digest_size: Integer
      ).returns(String)
    end
    def self.argon2id(password, salt, opslimit, memlimit, digest_size = 64); end
  end

  module Random
    sig { params(length: Integer).returns(String) }
    def self.random_bytes(length); end
  end
end
