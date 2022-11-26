# frozen_string_literal: true

RSpec.describe "PASERK k4.secret-wrap.pie Test Vectors" do
  it 'k4.secret-wrap.pie-1' do
    skip('requires RbNaCl') unless Paseto.rbnacl?
    unwrapped = '00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29'
    wrapping_key = Paseto::V4::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k4.secret-wrap.pie.NC6xj8t0VuK-0KE7Fy6PAKtbQwEFRyQMe39A0ctrkaIcS1zjVgvYTN6cu1AZM7bU2bz-jzKclAWu3Bln6xhSOsUqcQPi6Kw_LtKXLRCeggiuPnaqWfIT4qacjXtXhFvOvDPye21fbWOPuoNM9VppuTzN0LzYDYgNYCPsbWt2n4c'
    nonce = Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4')

    key = wrapping_key.unwrap(paserk)
    expect(key.to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(wrapping_key.unwrap(wrapping_key.wrap(key)).to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(wrapping_key.wrap(key)).to start_with('k4.secret-wrap.pie.')
  end

  it 'k4.secret-wrap.pie-2' do
    skip('requires RbNaCl') unless Paseto.rbnacl?
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
    wrapping_key = Paseto::V4::Local.new(ikm: Paseto::Util.decode_hex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))
    paserk = 'k4.secret-wrap.pie.dYA31PP6a-d1Cyk3xt2Dz8kpGSlbpwkG5UyrLcgRspSvq1RUO1UQicQNE3-eXYUYGhXrG9zAVnR93tize-IPtiFEyO70U3bWEXd0uU7asDJQ19I3V2mf5OPIcKQl-TnY0XXtw5DPqY1yEFEbA9WTiDG0I3z6KTWA2z09NWm0OHQ'
    nonce = Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4')

    key = wrapping_key.unwrap(paserk)
    expect(key.to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(wrapping_key.unwrap(wrapping_key.wrap(key)).to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(wrapping_key.wrap(key)).to start_with('k4.secret-wrap.pie.')
  end

  it 'k4.secret-wrap.pie-fail-1' do
    skip('requires RbNaCl') unless Paseto.rbnacl?
    wrapping_key = Paseto::V4::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k4.secret-wrap.pie.AIA31PP6ad1Cyk3xt2Dz8kpGSlbpwkG5UyrLcgRspSvq1RUO1UQicQNE3eXYUYGhXrG9zAVnR93tizeIPtiFEyO70U3bWEXd0uU7asDJQ19I3V2mf5OPIcKQlTnY0XXtw5DPqY1yEFEbA9WTiDG0I3z6KTWA2z09NWm0OHQ'
    nonce = Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4')

    passed = false
    begin
      wrapping_key.unwrap(paserk)
    rescue Paseto::InvalidAuthenticator, Paseto::IncorrectKeyType
      passed = true
    end
    expect(passed).to be true
  end

  it 'k4.secret-wrap.pie-fail-2' do
    skip('requires RbNaCl') unless Paseto.rbnacl?
    wrapping_key = Paseto::V4::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k3.secret-wrap.pie._9Npd2vzpHCHdGYDQ5QFMc6Nirlv3ubsPPb-xJnh6cLImLhpirH_PDQWRIkmb95m-fc1XpqwY2QQbUkkvb2-_tznGQBt0Yg2-0Lux2MNxObkxDIfxfz5lD_tToF58BIuTh9_Pny0dy27HmJPnUBgy7JP2Je-h3doq6i0V2Q5hRA'
    nonce = Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4')

    passed = false
    begin
      wrapping_key.unwrap(paserk)
    rescue Paseto::InvalidAuthenticator, Paseto::IncorrectKeyType
      passed = true
    end
    expect(passed).to be true
  end
end
