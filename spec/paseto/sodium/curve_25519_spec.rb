# encoding: binary
# typed: false
# frozen_string_literal: true

RSpec.describe 'Paseto::Sodium::Curve25519', :sodium do
  let(:described_class) { Paseto::Sodium::Curve25519 }

  let(:ed25519_keypair) do
    ['b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd' \
     '77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb'].pack('H*')
  end
  let(:x25519_sk) { ['38e5cdf33bc9e13086f58a3fea86d574e85e7865cffa5e8c9335f200a41d036c'].pack('H*') }
  let(:x25519_pk) { ['35488a98f7ec26ae27099809afb27587b198b1197b5bcb0dec41153db2bf9952'].pack('H*') }
  let(:key) { Paseto::V4::Public.from_keypair(ed25519_keypair) }

  describe '#to_x25519_private_key' do
    it 'converts a V4::Public key to X25519 SK form' do
      expect(described_class.new(key).to_x25519_private_key).to eq(x25519_sk)
    end
  end

  describe '#to_x25519_public_key' do
    it 'converts a V4::Public key to X25519 PK form' do
      expect(described_class.new(key).to_x25519_public_key).to eq(x25519_pk)
    end
  end
end
