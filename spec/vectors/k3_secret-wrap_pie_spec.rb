# frozen_string_literal: true

RSpec.describe "PASERK k3.secret-wrap.pie Test Vectors" do
  it 'k3.secret-wrap.pie-1' do
    unwrapped = '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001'
    wrapping_key = Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    public_key = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqofKIr6LBTeOscce8yCtdG4dO2KLp5uY\nWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR8\n6doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f\n-----END PUBLIC KEY-----\n"
    paserk = 'k3.secret-wrap.pie.hLBw_r4wY1mTy9hu27ibzOnFfW37jc3SER1fu3x2sh0cyE31abqEFzocZRg-KgAGY7syAoMsBZZi7ZlJ4xFreLdCi7cQWpIH3ejUQ5WIRMRDK2lh4X9knh2Bj26XaBOSqtK62ACF-V2utRiI3QVeOOLhH-GWuD8RovVQvA1Vv5Q'
    nonce = Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4')

    key = wrapping_key.unwrap(paserk)
    expect(key.to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(key.public_to_pem).to eq(public_key)
    expect(wrapping_key.wrap(key)).to start_with('k3.secret-wrap.pie.')
  end

  it 'k3.secret-wrap.pie-2' do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
    wrapping_key = Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))
    public_key = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGpkIIZKbJfvh5j3V+UbAlcqtBOX7kBNl\ni4NuyFryt6+mXLQnLsEgqNc3WZoM/UQnGjLUTWKk+uYYzEMSz23jEritEUAbnbLB\nMTAC++q74KVJGuNiwEKDHUb9rfXgjfdn\n-----END PUBLIC KEY-----\n"
    paserk = 'k3.secret-wrap.pie._9Npd2vzpHCHdGYDQ5QFMc6Nirlv3ubsPPb-xJnh6cLImLhpirH_PDQWRIkmb95m-fc1XpqwY2QQbUkkvb2-_tznGQBt0Yg2-0Lux2MNxObkxDIfxfz5lD_tToF58BIuTh9_Pny0dy27HmJPnUBgy7JP2Je-h3doq6i0V2Q5hRA'
    nonce = Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4')

    key = wrapping_key.unwrap(paserk)
    expect(key.to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(key.public_to_pem).to eq(public_key)
    expect(wrapping_key.wrap(key)).to start_with('k3.secret-wrap.pie.')
  end

  it 'k3.secret-wrap.pie-fail-1' do
    wrapping_key = Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))
    public_key = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGpkIIZKbJfvh5j3V+UbAlcqtBOX7kBNl\ni4NuyFryt6+mXLQnLsEgqNc3WZoM/UQnGjLUTWKk+uYYzEMSz23jEritEUAbnbLB\nMTAC++q74KVJGuNiwEKDHUb9rfXgjfdn\n-----END PUBLIC KEY-----\n"
    paserk = 'k3.secret-wrap.pie.ANNpd2vzpHCHdGYDQ5QFMc6Nirlv3ubsPPb-xJnh6cLImLhpirH_PDQWRIkmb95m-fc1XpqwY2QQbUkkvb2-_tznGQBt0Yg2-0Lux2MNxObkxDIfxfz5lD_tToF58BIuTh9_Pny0dy27HmJPnUBgy7JP2Je-h3doq6i0V2Q5hRA'
    nonce = Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4')

    passed = false
    begin
      wrapping_key.unwrap(paserk)
    rescue Paseto::InvalidAuthenticator, Paseto::LucidityError
      passed = true
    end
    expect(passed).to be true
  end

  it 'k3.secret-wrap.pie-fail-2' do
    wrapping_key = Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))
    paserk = 'k4.secret-wrap.pie.dYA31PP6a-d1Cyk3xt2Dz8kpGSlbpwkG5UyrLcgRspSvq1RUO1UQicQNE3-eXYUYGhXrG9zAVnR93tize-IPtiFEyO70U3bWEXd0uU7asDJQ19I3V2mf5OPIcKQl-TnY0XXtw5DPqY1yEFEbA9WTiDG0I3z6KTWA2z09NWm0OHQ'
    nonce = Paseto::Util.decode_hex('63bb3202832c059662ed9949e3116b78b7428bb7105a9207dde8d443958844c4')

    passed = false
    begin
      wrapping_key.unwrap(paserk)
    rescue Paseto::InvalidAuthenticator, Paseto::LucidityError
      passed = true
    end
    expect(passed).to be true
  end
end
