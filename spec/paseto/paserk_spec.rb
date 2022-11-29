# encoding: binary
# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Paserk do
  describe '.from_paserk' do
    subject(:key) { described_class.from_paserk(paserk: paserk, wrapping_key: wrapping_key) }

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
        expect(wrapping_key.wrap(key, nonce: nonce)).to eq(paserk)
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
        expect(wrapping_key.wrap(key, nonce: nonce)).to eq(paserk)
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
end
