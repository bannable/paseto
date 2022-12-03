# frozen_string_literal: true

RSpec.describe "PASERK k3.sid Test Vectors" do
it 'k3.sid-1' do
  ikm = Paseto::Util.decode_hex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001')
  paserk = %[k3.sid.DjlX1m4BBFtsnbwzw1zv_x0yRcrZpsvdr_gIxh_hg_Rv]

  key = Paseto::V3::Public.from_scalar_bytes(ikm)
  expect(key.id).to eq(paserk)
end

it 'k3.sid-2' do
  ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
  paserk = %[k3.sid.mNalRnF8T60OMPdi1TWSMcub-51v3Au2VB1MOqPrw8zG]

  key = Paseto::V3::Public.from_scalar_bytes(ikm)
  expect(key.id).to eq(paserk)
end

it 'k3.sid-3' do
  ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9ea0')
  paserk = %[k3.sid.2y01jpWJruAPv3epVJkTtDDvdHLsU3luYV9cvGgsR4C6]

  key = Paseto::V3::Public.from_scalar_bytes(ikm)
  expect(key.id).to eq(paserk)
end

it 'k3.sid-fail-1' do
  # Direct calls against Operations are not supported and the Key API prevents lucidity issues
end
end
