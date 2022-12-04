# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PKE
      extend T::Sig

      sig { params(sealing_key: AsymmetricKey).void }
      def initialize(sealing_key)
        case sealing_key
        in V3::Public
          coder = PKE::PKEv3
        in V4::Public if Paseto.rbnacl?
          coder = PKE::PKEv4
        else
          raise UnknownProtocol, 'not a valid version'
        end
        @sealing_key = sealing_key
        @coder = T.let(coder.new(@sealing_key), Interface::PKE)
      end

      sig { params(key: SymmetricKey).returns(String) }
      def encode(key)
        raise LucidityError unless key.protocol == @sealing_key.protocol

        esk = @coder.generate_ephemeral_key
        epk = esk.public_key

        xk = @sealing_key.ecdh(esk)

        @coder.derive_ek_n(xk: xk, epk: epk) => {ek:, n:}

        edk = @coder.crypt(message: key.to_bytes, ek: ek, n: n)

        ak = @coder.derive_ak(xk: xk, epk: epk)
        t = @coder.tag(ak: ak, epk: epk, edk: edk)

        epk_bytes = @coder.epk_bytes_from_esk(esk)
        data = Util.encode64("#{t}#{epk_bytes}#{edk}")
        "#{@coder.header}#{data}"
      end

      sig { params(paserk: String).returns(Interface::Key) }
      def decode(paserk)
        paserk.split('.') => [version, type, encoded_data]
        raise LucidityError unless version == @sealing_key.paserk_version
        raise LucidityError unless type == 'seal'

        @coder.decode(encoded_data)
      end
    end
  end
end
