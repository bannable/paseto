# encoding: binary
# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Paserk do
  subject(:key) do
    described_class.from_paserk(paserk:, wrapping_key:, password:, unsealing_key:)
  end

  let(:wrapping_key) { nil }
  let(:password) { nil }
  let(:unsealing_key) { nil }

  describe 'key wrapping' do
    let(:wrapping_key) do
      Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    end

    context 'when unwrapping secret-wrap.pie' do
      let(:paserk) do
        'k3.secret-wrap.pie.hLBw_r4wY1mTy9hu27ibzOnFfW37jc3SER1fu3x2sh0cyE31abqEFzocZRg-KgAGY7syAoMsBZZi7ZlJ4xFr' \
          'eLdCi7cQWpIH3ejUQ5WIRMRDK2lh4X9knh2Bj26XaBOSqtK62ACF-V2utRiI3QVeOOLhH-GWuD8RovVQvA1Vv5Q'
      end
      let(:nonce) { Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4') }

      # Not covered by PASERK test vectors as no nonce is provided
      it 'wraps correctly' do
        expect(wrapping_key.wrap(key, nonce:)).to eq(paserk)
      end
    end

    context 'when unwrapping local-wrap.pie' do
      let(:paserk) do
        'k3.local-wrap.pie.cLJLT84tUuU-ZLPqKWfhlDw4c2Fhk896z97sK2eM2-HYB3dk_NrHsSS340sJPsBsb7VeFpDBQMzzqRXr4Oylrp' \
          'zmg-NZC9FVqgaWm1gtEikm-1yvlGRYwstUFLvUF30NrBE3GxYzI63DqJPqfmHSmQ'
      end
      let(:nonce) { Paseto::Util.decode_hex('6fb55e1690c140ccf3a915ebe0eca5ae9ce683e3590bd155aa06969b582d1229') }

      # Not covered by PASERK test vectors as no nonce is provided
      it 'wraps correctly' do
        expect(wrapping_key.wrap(key, nonce:)).to eq(paserk)
      end
    end

    context 'when unwrapping an unrecognized protocol' do
      let(:paserk) { 'k3.local-wrap.TESTFOO.AAAAAAAAAAAAAAAAAAAAAAAA' }

      it 'raises an error' do
        expect { key }.to raise_error(Paseto::UnknownProtocol, 'TESTFOO')
      end
    end

    context 'when the unwrapped value violates algorithm lucidity' do
      let(:paserk) do
        'k3.secret-wrap.pie.uyS1qlPStZUy9qstDUV46danBHHOSrzehVHgq2QIGU9miiwMLLsvSlkEuiuoP-CcY7syAoMsBZZi7ZlJ4xFre' \
          'LdCi7cQWpIH3ejUQ5WIRMSWtcbAhwACuukCmDxyVqefTZiR0ZZOkDYXGThRlMxgWNLu5nUYrCtDCU0erBU'
      end

      it 'raises an error' do
        expect { key }.to raise_error(Paseto::InvalidKeyPair)
      end
    end

    context 'when the paserk version does not match the wrapping key version' do
      let(:paserk) { 'k1.secret-wrap.pie.foo' }

      it 'raises an error' do
        expect { key }.to raise_error(Paseto::LucidityError)
      end
    end

    context 'when the paserk includes no data' do
      let(:paserk) { 'k3.secret-wrap.pie.' }

      it 'raises an error' do
        expect { key }.to raise_error(Paseto::UnknownOperation)
      end
    end
  end

  describe 'v3.local' do
    let(:paserk) { 'k3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }

    it 'deserializes correctly' do
      expect(key.paserk).to eq(paserk)
    end
  end

  describe 'v3.public' do
    let(:paserk) { 'k3.public.AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }

    it 'deserializes correctly' do
      expect(key.paserk).to eq(paserk)
    end
  end

  describe 'v3.secret' do
    let(:paserk) { 'k3.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB' }

    it 'deserializes correctly' do
      expect(key.paserk).to eq(paserk)
    end
  end

  describe 'v4.local', :sodium do
    let(:paserk) { 'k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }

    it 'deserializes correctly' do
      expect(key.paserk).to eq(paserk)
    end
  end

  describe 'v4.public', :sodium do
    let(:paserk) { 'k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }

    it 'deserializes correctly' do
      expect(key.paserk).to eq(paserk)
    end
  end

  describe 'v4.secret', :sodium do
    let(:paserk) { 'k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ' }

    it 'deserializes correctly' do
      expect(key.paserk).to eq(paserk)
    end
  end

  describe 'v4.seal', :sodium do
    let(:paserk) do
      'k4.seal.OPFn-AEUsKUWtAUZrutVvd9YaZ4CmV4_lk6ii8N72l5gTnl8RlL_zRFq' \
        'WTZZV9gSnPzARQ_QklrZ2Qs6cJGKOENNOnsDXL5haXcr-QbTXgoLVBvT4ruJ8MdjWXGRTVc9'
    end
    let(:keypair) do
      '407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1d' \
        'b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023'
    end
    let(:unsealing_key) { Paseto::V4::Public.from_keypair([keypair].pack('H*')) }

    it 'deserializes correctly' do
      expect(key.to_bytes).to eq("\x00" * 32)
    end
  end

  describe 'v3.seal' do
    let(:paserk) do
      'k3.seal.NsI9NFzAouTSs7V5mejAeyBLYcoeNlbb9eY8C2KnkPTsARsPLen9KfMF' \
        'fgqeI50FAnuRCdcb4HmXPaY3i-ZdBXwfdqSiB_65lmIHosVOJ7chmqqscnBkA7vc' \
        '3mEAXxM05hSytjBYFxwlUnfFE3Sq3YHUZrOELF7PM87K6FFOMqc6'
    end
    let(:pem) do
      <<~P384
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L
        JpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb
        TzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE
        zjhi6u4sNgzW23rrVkRYkb2oE3SJPko=
        -----END EC PRIVATE KEY-----
      P384
    end
    let(:unsealing_key) { Paseto::V3::Public.new(pem) }

    it 'deserializes correctly' do
      expect(key.to_bytes).to eq("\x00" * 32)
    end
  end
end
