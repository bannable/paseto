# frozen_string_literal: true

RSpec.describe "PASERK k4.pid Test Vectors" do
it 'k4.pid-1', :sodium do
  ikm = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
  paserk = %[k4.pid.S_XQmeEwHbbvRmiyfXfHYpLGjXGzjTRSDoT1YtTakWFE]

  key = Paseto::V4::Public.from_public_bytes(ikm)
  expect(key.id).to eq(paserk)
end

it 'k4.pid-2', :sodium do
  ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
  paserk = %[k4.pid.9ShR3xc8-qVJ_di0tc9nx0IDIqbatdeM2mqLFBJsKRHs]

  key = Paseto::V4::Public.from_public_bytes(ikm)
  expect(key.id).to eq(paserk)
end

it 'k4.pid-3', :sodium do
  ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90')
  paserk = %[k4.pid.-nyvbaTz8U6TQz7OZWW-iB3va31iAxIpUgzUcVQVmW9A]

  key = Paseto::V4::Public.from_public_bytes(ikm)
  expect(key.id).to eq(paserk)
end

it 'k4.pid-fail-1', :sodium do
  # Direct calls against Operations are not supported and the Key API prevents lucidity issues
end

it 'k4.pid-fail-2', :sodium do
  # Direct calls against Operations are not supported and the Key API prevents lucidity issues
end
end
