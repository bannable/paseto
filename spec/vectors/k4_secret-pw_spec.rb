# frozen_string_literal: true

RSpec.describe "PASERK k4.secret-pw Test Vectors" do
  it 'k4.secret-pw-1', :sodium do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>67108864, :opslimit=>2}
    paserk = 'k4.secret-pw.g5CZn27bLJQkPVOYjrWEQAAAAAAEAAAAAAAAAgAAAAGpohE13nAyCtWfj2Xf3rgORRrE1X0qw2U1FWSJm_6snSbneAqz59FTgsmUR2cNmC41rauCVViAEijox_mY4iJzIUOv34cHkLLIZ_te-FpqKDK0bFtH-rgdFkiy-RjCG0EN349NFFqCZHu7gOlQw98nyeRwWelHCJE'

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = key.pbkd(password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k4.secret-pw-2', :slow, :sodium do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.secret-pw.1n54ImYiJUSDhTn7vzBI4QAAAAAQAAAAAAAAAwAAAAFBZythnpR02Zza64_y9DuKHeyZVEP_vZx0Y721aIry1rZc70cR08Jb2rgV4pcqR9in25TvA4pV7L4kT3r-0b-5a8Z7wk35D0zOnPLEJloAHf2XEYGleFReV2-tiV1T79G6OhlATgd-bJbXjRqlEOCsk_-pRdSsCeE'

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = key.pbkd(password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k4.secret-pw-3', :slow, :sodium do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = 'correct horse battery staple'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.secret-pw.l7bNRB3P5Pwp2FN11-O5dgAAAAAQAAAAAAAAAwAAAAGMe2vxUAZ5quIB-7KCN6_zP_rFqqPmgaVI8ut4xvM2QZQ7QNpr4MlmZ52UulTstEf0uT8vyWzn7bthOALA2ZH_0iBiG9pPWqD8UzmuUjUP5Yi92B_5pUw3DJ0vwNP-GgvjHQObQXLsWPfe_exECoYAWdkI6q-VtSM'

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = key.pbkd(password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k4.secret-pw-fail-1', :slow, :sodium do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = '636f727265637420686f727365206261747465727920737461706c66'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.secret-pw.1n54ImYiJUSDhTn7vzBI4QAAAAAQAAAAAAAAAwAAAAFBZythnpR02Zza64_y9DuKHeyZVEP_vZx0Y721aIry1rZc70cR08Jb2rgV4pcqR9in25TvA4pV7L4kT3r-0b-5a8Z7wk35D0zOnPLEJloAHf2XEYGleFReV2-tiV1T79G6OhlATgd-bJbXjRqlEOCsk_-pRdSsCeE'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    expect do
      Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    end.to raise_error(Paseto::InvalidAuthenticator)

    expect do
      pbkw.encode(Paseto::V3::Local.new(ikm: 0.chr * 32), options)
    end.to raise_error(Paseto::LucidityError)
  end

  it 'k4.secret-pw-fail-2', :slow, :sodium do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.secret-pw.AH54ImYiJUSDhTn7vzBI4QAAAAAQAAAAAAAAAwAAAAFBZythnpR02Zza64_y9DuKHeyZVEP_vZx0Y721aIry1rZc70cR08Jb2rgV4pcqR9in25TvA4pV7L4kT3r-0b-5a8Z7wk35D0zOnPLEJloAHf2XEYGleFReV2-tiV1T79G6OhlATgd-bJbXjRqlEOCsk_-pRdSsCeE'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    expect do
      Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    end.to raise_error(Paseto::InvalidAuthenticator)

    expect do
      pbkw.encode(Paseto::V3::Local.new(ikm: 0.chr * 32), options)
    end.to raise_error(Paseto::LucidityError)
  end

  it 'k4.secret-pw-fail-3', :slow, :sodium do
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k3.secret-pw.LajP_XFziwwUW8t0xppL3ecIgaOzfSEx-5-UQG36jJ8AACcQUeD46ydUwIkMOqkXWFvacyf_eaH1BTMlJsdCy6ZhemmaFMZTclOD9LrOwCVnmhlCDQEePilxQEfvPsRM5cL_yxx1bWL0wjS4GAQABQiCvGyQTi_LGlbMnYuiZfxWgpqNJpAI6jx71m6s3f6wZIg68Q'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    expect { pbkw.decode(paserk) }.to raise_error(Paseto::LucidityError)

    expect do
      pbkw.encode(Paseto::V3::Local.new(ikm: 0.chr * 32), options)
    end.to raise_error(Paseto::LucidityError)
  end
end
