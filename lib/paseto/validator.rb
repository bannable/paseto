# typed: strict
# frozen_string_literal: true

module Paseto
  class Validator
    extend T::Sig
    extend T::Helpers

    abstract!

    sig { returns(T::Hash[String, T.untyped]) }
    attr_reader :payload

    sig { returns(T::Hash[Symbol, T.untyped]) }
    attr_reader :options

    sig { params(payload: T::Hash[String, T.untyped], options: T::Hash[Symbol, T.untyped]).void }
    def initialize(payload, options)
      @payload = payload
      @options = options
    end

    sig { abstract.void }
    def verify; end

    class Audience < Validator
      sig { override.void }
      def verify
        return unless (aud = options[:verify_aud])

        given = payload['aud']
        raise InvalidAudience, "Invalid audience. Expected #{aud}, got #{given || '<none>'}" if ([*aud] & [*given]).empty?
      end
    end

    class Expiration < Validator
      sig { override.void }
      def verify
        return unless options[:verify_exp]

        given = payload['exp']
        begin
          exp = Time.iso8601(given)
        rescue ArgumentError
          raise ExpiredToken, "Expiry not valid iso8601, got #{given || '<none>'}"
        end

        raise ExpiredToken, 'Expiry has passed' if Time.now > exp
      end
    end

    class IssuedAt < Validator
      sig { override.void }
      def verify
        return unless options[:verify_iat]

        given = payload['iat']
        begin
          iat = Time.iso8601(given)
        rescue ArgumentError
          raise ImmatureToken, "IssuedAt not valid iso8601, got #{given || '<none>'}"
        end

        raise ImmatureToken, 'Token is from the future' if Time.now < iat
      end
    end

    class Issuer < Validator
      sig { override.void }
      def verify
        return unless (permitted = options[:verify_iss])

        given = payload['iss']
        permitted = Array(permitted).map { |i| i.is_a?(Symbol) ? i.to_s : i }

        case given
        when *permitted
          nil
        else
          raise InvalidIssuer, "Invalid issuer. Expected #{permitted}, got #{given || '<none>'}"
        end
      end
    end

    class WPK < Validator
      PERMITTED = T.let(%w(seal local-wrap secret-wrap), T::Array[String])

      sig { override.void }
      def verify
        return unless (wpk = payload['wpk'])

        wpk.split('.', 3) => [_, String => type, _]
        raise InvalidWPK unless PERMITTED.include?(type)
      end
    end

    class KeyID < Validator
      PERMITTED = T.let(%w(lid sid pid), T::Array[String])

      sig { override.void }
      def verify
        return unless (kid = payload['kid'])

        case kid.split('.')
        in [_, String => type, _] if PERMITTED.include?(type)
          nil
        else
          raise InvalidKID
        end
      end
    end

    class NotBefore < Validator
      sig { override.void }
      def verify
        return unless options[:verify_nbf]

        given = payload['nbf']
        begin
          nbf = Time.iso8601(given)
        rescue ArgumentError
          raise InactiveToken, "NotBefore not valid iso8601, got #{given || '<none>'}"
        end

        raise InactiveToken, 'Not yet active' if nbf > Time.now
      end
    end

    class Subject < Validator
      sig { override.void }
      def verify
        return unless (sub = options[:verify_sub])

        given = payload['sub']

        raise InvalidSubject, "Invalid subject. Expected #{sub}, got #{given || '<none>'}" unless sub == given
      end
    end

    class TokenIdentifier < Validator
      sig { override.void }
      def verify
        return unless (jti = options[:verify_jti])

        given = payload['jti']
        if jti.respond_to?(:call)
          raise InvalidTokenIdentifier, 'Invalid jti' unless jti.call(given)
        elsif given.to_s.empty?
          raise InvalidTokenIdentifier, 'Missing jti'
        end
      end
    end
  end
end
