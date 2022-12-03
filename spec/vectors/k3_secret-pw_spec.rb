# frozen_string_literal: true

RSpec.describe "PASERK k3.secret-pw Test Vectors" do
  it 'k3.secret-pw-1', :slow do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:iterations=>1000}
    paserk = 'k3.secret-pw.kgGHkPhCK_nclk8kpCqJuTPM7BYfGxSwdeXETNnRglIAAAPonBRPeN3eNgUEMZAY9mLaQPXmg6zMls48IjN4429EoIyS2No-EGpKv6eRb_Zh65PdEec1pq0SaMWb434A2eqd4vt4_wcTfdobxiNovASIgyry03qnjx29FmuZ2bIvNzh-YExE_AA7UFDzs6BHom8F9Q'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = Paseto::Paserk.pbkw(key: key, password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k3.secret-pw-2', :slow do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:iterations=>10000}
    paserk = 'k3.secret-pw.LajP_XFziwwUW8t0xppL3ecIgaOzfSEx-5-UQG36jJ8AACcQUeD46ydUwIkMOqkXWFvacyf_eaH1BTMlJsdCy6ZhemmaFMZTclOD9LrOwCVnmhlCDQEePilxQEfvPsRM5cL_yxx1bWL0wjS4GAQABQiCvGyQTi_LGlbMnYuiZfxWgpqNJpAI6jx71m6s3f6wZIg68Q'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = Paseto::Paserk.pbkw(key: key, password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k3.secret-pw-3', :slow do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = 'correct horse battery staple'
    options = {:iterations=>10000}
    paserk = 'k3.secret-pw._67v-WS5Jcez0HggRU2WqRDQewjO2cTKfLwsv2smSd0AACcQC-kvhegUybh2VVNQ4TU68Uqlg9ZOlPzmT36bpDsFc1vF2Lw5Jg8WRRuX1Bg3KT6GN1sUoAW95iuc2OnyIXNpDKXIA6FRPKkpztCVHiWFhEtiIUeGOg8hh11eueUNz4GmfCH91TNz2KtbAvy1TXT5Lw'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = Paseto::Paserk.pbkw(key: key, password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k3.secret-pw-fail-1', :slow do
    password = '636f727265637420686f727365206261747465727920737461706c66'
    options = {:iterations=>10000}
    paserk = 'k3.secret-pw.LajP_XFziwwUW8t0xppL3ecIgaOzfSEx-5-UQG36jJ8AACcQUeD46ydUwIkMOqkXWFvacyf_eaH1BTMlJsdCy6ZhemmaFMZTclOD9LrOwCVnmhlCDQEePilxQEfvPsRM5cL_yxx1bWL0wjS4GAQABQiCvGyQTi_LGlbMnYuiZfxWgpqNJpAI6jx71m6s3f6wZIg68Q'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    expect do
      Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    end.to raise_error(Paseto::InvalidAuthenticator)

    if Paseto.rbnacl?
      expect do
        pbkw.encode(Paseto::V4::Local.new(ikm: 0.chr * 32), options)
      end.to raise_error(Paseto::LucidityError)
    end
  end

  it 'k3.secret-pw-fail-2', :slow do
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:iterations=>10000}
    paserk = 'k3.secret-pw.AKjP_XFziwwUW8t0xppL3ecIgaOzfSEx-5-UQG36jJ8AACcQUeD46ydUwIkMOqkXWFvacyf_eaH1BTMlJsdCy6ZhemmaFMZTclOD9LrOwCVnmhlCDQEePilxQEfvPsRM5cL_yxx1bWL0wjS4GAQABQiCvGyQTi_LGlbMnYuiZfxWgpqNJpAI6jx71m6s4f6wZIg68Q'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    expect do
      Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    end.to raise_error(Paseto::InvalidAuthenticator)

    if Paseto.rbnacl?
      expect do
        pbkw.encode(Paseto::V4::Local.new(ikm: 0.chr * 32), options)
      end.to raise_error(Paseto::LucidityError)
    end
  end

  it 'k3.secret-pw-fail-3', :slow do
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.secret-pw.1n54ImYiJUSDhTn7vzBI4QAAAAAQAAAAAAAAAwAAAAFBZythnpR02Zza64_y9DuKHeyZVEP_vZx0Y721aIry1rZc70cR08Jb2rgV4pcqR9in25TvA4pV7L4kT3r-0b-5a8Z7wk35D0zOnPLEJloAHf2XEYGleFReV2-tiV1T79G6OhlATgd-bJbXjRqlEOCsk_-pRdSsCeE'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    expect do
      pbkw.decode(paserk)
    end.to raise_error(Paseto::LucidityError)

    if Paseto.rbnacl?
      expect do
        pbkw.encode(Paseto::V4::Local.new(ikm: 0.chr * 32), options)
      end.to raise_error(Paseto::LucidityError)
    end
  end
end
