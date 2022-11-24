# encoding: binary
# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Paserk do
  describe '.from_paserk' do
    subject(:key) { described_class.from_paserk(paserk: paserk, wrapping_key: wrapping_key) }

    let(:wrapping_key) { Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f') }

    context 'secret-wrap.pie' do
      let(:unwrapped) do
        <<~UNWRAPPED
          -----BEGIN PUBLIC KEY-----
          MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqofKIr6LBTeOscce8yCtdG4dO2KLp5uY
          WfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR8
          6doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f
          -----END PUBLIC KEY-----
        UNWRAPPED
      end
      let(:paserk) do
        'k3.secret-wrap.pie.hLBw_r4wY1mTy9hu27ibzOnFfW37jc3SER1fu3x2sh0cyE31abqEFzocZRg-KgAGY7syAoMsBZZi7ZlJ4xFreLdCi7cQWpIH3ejUQ5WIRMRDK2lh4X9knh2Bj26XaBOSqtK62ACF-V2utRiI3QVeOOLhH-GWuD8RovVQvA1Vv5Q'
      end
      let(:nonce) { Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4') }

      it { is_expected.to be_a(Paseto::V3::Public) }

      it 'unwraps correctly' do
        expect(key.public_to_pem).to eq(unwrapped)
      end

      it 'wraps correctly' do
        expect(key.wrap(wrapping_key, nonce: nonce)).to eq(paserk)
      end
    end

    context 'local-wrap.pie' do
      let(:unwrapped) { Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000') }
      let(:paserk) do
        'k3.local-wrap.pie.cLJLT84tUuU-ZLPqKWfhlDw4c2Fhk896z97sK2eM2-HYB3dk_NrHsSS340sJPsBsb7VeFpDBQMzzqRXr4Oylrpzmg-NZC9FVqgaWm1gtEikm-1yvlGRYwstUFLvUF30NrBE3GxYzI63DqJPqfmHSmQ'
      end
      let(:nonce) { Paseto::Util.decode_hex('6fb55e1690c140ccf3a915ebe0eca5ae9ce683e3590bd155aa06969b582d1229') }

      it { is_expected.to be_a(Paseto::V3::Local) }

      it 'unwraps correctly' do
        expect(key.key).to eq(unwrapped)
      end

      it 'wraps correctly' do
        expect(key.wrap(wrapping_key, nonce: nonce)).to eq(paserk)
      end
    end

    context 'with an unrecognized protocol' do
      let(:paserk) { 'k3.local-wrap.TESTFOO.AAAAAAAAAAAAAAAAAAAAAAAA' }

      it 'raises an error' do
        expect { key }.to raise_error(Paseto::Paserk::UnrecognizedProtocol)
      end
    end
  end
end
