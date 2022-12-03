# frozen_string_literal: true

RSpec.describe "PASERK k3.lid Test Vectors" do
  it 'k3.lid-1' do
    ikm = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
    paserk = %[k3.lid.c2Wpke9KunV6-Tow8dV1wsvVFRkjcTYt_7ZzOtIDRFpM]

    key = Paseto::V3::Local.new(ikm: ikm)
    expect(key.id).to eq(paserk)
  end

  it 'k3.lid-2' do
    ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    paserk = %[k3.lid.5GB-DfqfPOIMr0-y4IV8323vrjMt3mZMh_R3J3raH38l]

    key = Paseto::V3::Local.new(ikm: ikm)
    expect(key.id).to eq(paserk)
  end

  it 'k3.lid-3' do
    ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90')
    paserk = %[k3.lid.Gd3T6cJNElhwD4gu9JXlaysLNClYmFTD6GRUnXRotCEr]

    key = Paseto::V3::Local.new(ikm: ikm)
    expect(key.id).to eq(paserk)
  end

  it 'k3.lid-fail-1' do
    # It is not possible to construct the necessary SymmetricKey
  end
end
