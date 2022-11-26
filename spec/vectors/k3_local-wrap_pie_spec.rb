# frozen_string_literal: true

RSpec.describe "PASERK k3.local-wrap.pie Test Vectors" do
  it 'k3.local-wrap.pie-1' do
    unwrapped = '0000000000000000000000000000000000000000000000000000000000000000'
    wrapping_key = Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k3.local-wrap.pie.cLJLT84tUuU-ZLPqKWfhlDw4c2Fhk896z97sK2eM2-HYB3dk_NrHsSS340sJPsBsb7VeFpDBQMzzqRXr4Oylrpzmg-NZC9FVqgaWm1gtEikm-1yvlGRYwstUFLvUF30NrBE3GxYzI63DqJPqfmHSmQ'

    key = wrapping_key.unwrap(paserk)
    expect(key.key.unpack1('H*')).to eq(unwrapped)
    expect(wrapping_key.wrap(key)).to start_with('k3.local-wrap.pie')
  end

  it 'k3.local-wrap.pie-2' do
    unwrapped = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    wrapping_key = Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k3.local-wrap.pie.bkbHfW4bBJQ8jcPfLOYxUrg4SkKRHbsywYZwRvxUGFt1je2idZxlFr8sbkB6jTZ6hnrVlI25G2hqZtfdQyFIUcrRAiBrCWNPP1b3afdD9_YxsAXoKEA3X4AZhReuvHCzuPqXNCtrvJtpupGZn-PLFQ'

    key = wrapping_key.unwrap(paserk)
    expect(key.key.unpack1('H*')).to eq(unwrapped)
    expect(wrapping_key.wrap(key)).to start_with('k3.local-wrap.pie')
  end

  it 'k3.local-wrap.pie-fail-1' do
    wrapping_key = Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k3.local-wrap.pie.bkbHfW4bBJQ8jcPfLOYxUrg4SkKRHbsywYZwRvxUGFt1je2idZxlFr8sbkB6jTZ6hnrVlI25G2hqZtfdQyFIUcrRAiBrCWNPP1b3afdD9_YxsAXoKEA3X4AZhReuvHCzuPqXNCtrvJtpupHZo-RLFQ'

    passed = false
    begin
      wrapping_key.unwrap(paserk)
    rescue Paseto::InvalidAuthenticator, Paseto::IncorrectKeyType
      passed = true
    end
    expect(passed).to be true
  end

  it 'k3.local-wrap.pie-fail-2' do
    wrapping_key = Paseto::V3::Local.new(ikm: Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'))
    paserk = 'k4.local-wrap.pie.cy-Mu6zSfhu6q0_XdAM9p1zre_joUWjreSjHgisVNh-oHaNarN4_c7xuSyaHwqEDxF7lTbfNplBGU7wTeUyt__hZyj1J38NdNxVwuXamJY2QhRE-kWYA9_16xTsGwCQX'

    passed = false
    begin
      wrapping_key.unwrap(paserk)
    rescue Paseto::InvalidAuthenticator, Paseto::IncorrectKeyType
      passed = true
    end
    expect(passed).to be true
  end
end
