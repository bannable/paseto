# typed: strict
# frozen_string_literal: true

module Paseto
  module Configuration
    class DecodeConfiguration
      extend T::Sig

      sig { returns(Interface::Serializer) }
      attr_accessor :footer_serializer

      sig { returns(T::Boolean) }
      attr_accessor :verify_exp, :verify_nbf, :verify_iat

      sig { returns(T.any(FalseClass, String)) }
      attr_accessor :verify_sub

      sig { returns(T.any(FalseClass, T::Array[String])) }
      attr_accessor :verify_aud

      sig { returns(T.any(T::Array[T.any(String, Regexp, T.proc.params(issuer: String).returns(T::Boolean))], FalseClass)) }
      attr_accessor :verify_iss

      sig do
        returns(T.any(
                  T::Boolean,
                  T.proc.params(jti: String).returns(T::Boolean)
                ))
      end
      attr_accessor :verify_jti

      sig { void }
      def initialize # rubocop:disable Metrics/AbcSize
        @footer_serializer = T.let(Serializer::OptionalJson, Interface::Serializer)
        @verify_exp = T.let(true, T::Boolean)
        @verify_nbf = T.let(true, T::Boolean)
        @verify_iat = T.let(true, T::Boolean)

        @verify_iss = T.let(false, T.any(FalseClass,
                                         T::Array[
                                          T.any(String, Regexp, T.proc.params(issuer: String).returns(T::Boolean))
                                          ]))

        @verify_aud = T.let(false, T.any(FalseClass, T::Array[String]))

        @verify_sub = T.let(false, T.any(FalseClass, String))

        @verify_jti = T.let(false, T.any(
                                     T::Boolean,
                                     T.proc.params(jti: String).returns(T::Boolean)
                                   ))
      end

      sig { returns(T::Hash[Symbol, T.untyped]) }
      def to_h
        {
          verify_exp:,
          verify_nbf:,
          verify_iss:,
          verify_iat:,
          verify_jti:,
          verify_aud:,
          verify_sub:
        }
      end
    end
  end
end
