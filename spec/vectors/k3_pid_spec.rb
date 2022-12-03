# frozen_string_literal: true

RSpec.describe "PASERK k3.pid Test Vectors" do
it 'k3.pid-1' do
  ikm = Paseto::Util.decode_hex('02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
  paserk = %[k3.pid.mL4lGxNG7cz128frmpn83_76V9C7LmV2sHAMtJ8vIdwG]

  key = Paseto::V3::Public.from_public_bytes(ikm)
  expect(key.id).to eq(paserk)
end

it 'k3.pid-2' do
  ikm = Paseto::Util.decode_hex('02707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
  paserk = %[k3.pid.gnwg7IkzZyQF9wJgLLT0OpbdMT7BYmdQoG2u-xXpeeHz]

  key = Paseto::V3::Public.from_public_bytes(ikm)
  expect(key.id).to eq(paserk)
end

it 'k3.pid-fail-1' do
  # Direct calls against Operations are not supported and the Key API prevents lucidity issues
end

it 'k3.pid-fail-2' do
  # Direct calls against Operations are not supported and the Key API prevents lucidity issues
end
end
