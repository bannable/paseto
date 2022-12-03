# frozen_string_literal: true

RSpec.describe "PASERK k4.local-wrap.pie Test Vectors" do
  it 'k4.local-wrap.pie-1', :sodium do
    unwrapped = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
    wrapping_key = Paseto::V4::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k4.local-wrap.pie.y-PC8Zh6P1DoOBUdhRr7W8GWSgHtRKvE8PWWYA-qXy3fxJDmaRsxcZVQzuvXHZuBg5MqCgh_y5K0WbukJCrDX73Wdf631VBnE1DNHafbjnGNzFNWP59ba9ifsOAgE7Bw'

    key = wrapping_key.unwrap(paserk)
    expect(key.key).to eq(unwrapped)
    expect(wrapping_key.wrap(key)).to start_with('k4.local-wrap.pie')
  end

  it 'k4.local-wrap.pie-2', :sodium do
    unwrapped = Paseto::Util.decode_hex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    wrapping_key = Paseto::V4::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k4.local-wrap.pie.cy-Mu6zSfhu6q0_XdAM9p1zre_joUWjreSjHgisVNh-oHaNarN4_c7xuSyaHwqEDxF7lTbfNplBGU7wTeUyt__hZyj1J38NdNxVwuXamJY2QhRE-kWYA9_16xTsGwCQX'

    key = wrapping_key.unwrap(paserk)
    expect(key.key).to eq(unwrapped)
    expect(wrapping_key.wrap(key)).to start_with('k4.local-wrap.pie')
  end

  it 'k4.local-wrap.pie-fail-1', :sodium do
    wrapping_key = Paseto::V4::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k4.local-wrap.pie.cy-Mu6zSfhu6q0_XdAM9p1zre_joUWjreSjHgisVNh-oHaNarN4_c7xuSyaHwqEDxF7lTbfNplBGU7wTeUyt__hZyj1J38NdNxVwuXamJY3QhRE-kWYA9_16xUtGwCQY'

    passed = false
    begin
      wrapping_key.unwrap(paserk)
    rescue Paseto::InvalidAuthenticator, Paseto::LucidityError
      passed = true
    end
    expect(passed).to be true
  end

  it 'k4.local-wrap.pie-fail-2', :sodium do
    wrapping_key = Paseto::V4::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k3.local-wrap.pie.bkbHfW4bBJQ8jcPfLOYxUrg4SkKRHbsywYZwRvxUGFt1je2idZxlFr8sbkB6jTZ6hnrVlI25G2hqZtfdQyFIUcrRAiBrCWNPP1b3afdD9_YxsAXoKEA3X4AZhReuvHCzuPqXNCtrvJtpupGZn-PLFQ'

    passed = false
    begin
      wrapping_key.unwrap(paserk)
    rescue Paseto::InvalidAuthenticator, Paseto::LucidityError
      passed = true
    end
    expect(passed).to be true
  end
end
