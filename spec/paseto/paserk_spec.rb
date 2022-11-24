# encoding: binary
# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Paserk do
  describe '.from_paserk' do
    subject(:key) { described_class.from_paserk(paserk: paserk, wrapping_key: wrapping_key) }

    let(:wrapping_key) { Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f') }

    context 'secret-wrap.pie' do
      let(:unwrapped) { Paseto::Util.decode_hex('2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d485977454159484b6f5a497a6a3043415159464b3445454143494459674145716f664b4972364c4254654f7363636538794374644734644f324b4c703575590a5766644234494a554b6a685641764a647631557062447055586a6879646771334e6866655370596d4c4739646e70692f6b704c634b666a304862306f6d6852380a36646f7845375877754d414b594c484f485836426e58704448587951366735660a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d')}
      let(:paserk) { 'k3.secret-wrap.pie.hLBw_r4wY1mTy9hu27ibzOnFfW37jc3SER1fu3x2sh0cyE31abqEFzocZRg-KgAGY7syAoMsBZZi7ZlJ4xFreLdCi7cQWpIH3ejUQ5WIRMRDK2lh4X9knh2Bj26XaBOSqtK62ACF-V2utRiI3QVeOOLhH-GWuD8RovVQvA1Vv5Q' }

      it { is_expected.to be_a(Paseto::V3::Public) }

      it 'unwraps correctly' do
        expect(key.public_to_pem).to eq(unwrapped)
      end
    end

    context 'local-wrap.pie' do
      let(:unwrapped) { Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000') }
      let(:paserk) { 'k3.local-wrap.pie.cLJLT84tUuU-ZLPqKWfhlDw4c2Fhk896z97sK2eM2-HYB3dk_NrHsSS340sJPsBsb7VeFpDBQMzzqRXr4Oylrpzmg-NZC9FVqgaWm1gtEikm-1yvlGRYwstUFLvUF30NrBE3GxYzI63DqJPqfmHSmQ' }

      it { is_expected.to be_a(Paseto::V3::Local) }

      it 'unwraps correctly' do
        expect(key.key).to eq(unwrapped)
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
