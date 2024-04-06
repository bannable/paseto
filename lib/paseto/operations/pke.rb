# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PKE
      extend T::Sig

      sig { params(sealing_key: AsymmetricKey).void }
      def initialize(sealing_key)
        @sealing_key = sealing_key
        @coder = T.let(@sealing_key.pke, Paseto::Interface::PKE)
      end

      sig { params(key: SymmetricKey).returns(String) }
      def seal(key)
        raise LucidityError unless key.protocol == @sealing_key.protocol

        esk = @coder.generate_ephemeral_key
        epk = esk.public_key

        xk = @sealing_key.ecdh(esk)

        @coder.derive_ek_n(xk:, epk:) => {ek:, n:}

        edk = @coder.encrypt(message: key.to_bytes, ek:, n:)

        ak = @coder.derive_ak(xk:, epk:)
        t = @coder.tag(ak:, epk:, edk:)

        epk_bytes = @coder.epk_bytes_from_esk(esk)
        data = Util.encode64("#{t}#{epk_bytes}#{edk}")
        "#{@coder.header}#{data}"
      end

      sig { params(paserk: String).returns(Interface::Key) }
      def unseal(paserk)
        paserk.split('.') => [version, type, encoded_data]
        raise LucidityError unless version == @sealing_key.paserk_version && type == 'seal'

        t, epk, edk = @coder.split(encoded_data)

        xk = @sealing_key.ecdh(epk)

        ak = @coder.derive_ak(xk:, epk:)
        t2 = @coder.tag(ak:, epk:, edk:)
        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        @coder.derive_ek_n(xk:, epk:) => {ek:, n:}

        @coder.decrypt(message: edk, ek:, n:)
      end
    end
  end
end
