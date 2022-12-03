# frozen_string_literal: true

RSpec.describe "PASERK k4.sid Test Vectors" do
it 'k4.sid-1', :sodium do
  ikm = Paseto::Util.decode_hex('00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29')
  paserk = %[k4.sid.YujQ-NvcGquQ0Q-arRf8iYEcXiSOKg2Vk5az-n1lxiUd]

  key = Paseto::V4::Public.from_keypair(ikm)
  expect(key.id).to eq(paserk)
end

it 'k4.sid-2', :sodium do
  ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35')
  paserk = %[k4.sid.gHYyx8y5YzqKEZeYoMDqUOKejdSnY_AWhYZiSCMjR1V5]

  key = Paseto::V4::Public.from_keypair(ikm)
  expect(key.id).to eq(paserk)
end

it 'k4.sid-3', :sodium do
  ikm = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e9060fe37571a5d6e7d30b15154ce4a9fb92c70c870848f4ccdf1626588097f73f7')
  paserk = %[k4.sid.2_m4h6ZTO3qm_PIpl-eYyAqTbNTgmIPQ85POmUEyZHNd]

  key = Paseto::V4::Public.from_keypair(ikm)
  expect(key.id).to eq(paserk)
end

it 'k4.sid-fail-1', :sodium do
  # Direct calls against Operations are not supported and the Key API prevents lucidity issues
end
end
