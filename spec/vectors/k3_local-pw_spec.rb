# frozen_string_literal: true

RSpec.describe "PASERK k3.local-pw Test Vectors" do
  it 'k3.local-pw-1' do
    # skip('slow tests run only on command in CI') if ENV['CI'] && !ENV['SLOW_CI']
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:iterations=>1000}
    paserk = 'k3.local-pw.meWTPJohkeLsaKvlgigDksM935uSCUO3jvjEEHAK28QAAAPoNoLFUMJwo8QHOp5bJpbNzk-ZD_Q6jPtk0XhX4ctVhZnJ3ydru5AuXObwRudmG_RNK3PsJ7kpLSw15Vncc5vmGIkae4DKmBmPI1h3PmOxMGX_hj9DNfu1MIEEm9ukhKQq'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    key = pbkw.decode(paserk)
    expect(key.to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(pbkw.decode(pbkw.encode(key, options)).to_bytes.unpack1('H*')).to eq(unwrapped)
  end

  it 'k3.local-pw-2' do
    # skip('slow tests run only on command in CI') if ENV['CI'] && !ENV['SLOW_CI']
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:iterations=>10000}
    paserk = 'k3.local-pw.BZtl8KfhFR8CCZp6hB0V2yMWttTMpK_U8HiKxnuvMI0AACcQIm4KcJGvG1kfptqCbQxzQUOp72AzgtmhCLVP1mn3orDRJIpoDzRj82dc1cMnANbUsEdcYVG8xzSuCt99zfCjQnQ2rIKbKRM66gafzcSWmD9iMoY3W6KUaN56t0P-ODV2'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    key = pbkw.decode(paserk)
    expect(key.to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(pbkw.decode(pbkw.encode(key, options)).to_bytes.unpack1('H*')).to eq(unwrapped)
  end

  it 'k3.local-pw-3' do
    # skip('slow tests run only on command in CI') if ENV['CI'] && !ENV['SLOW_CI']
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
    unwrapped_raw = Paseto::Util.decode_hex(unwrapped)
    password = 'correct horse battery staple'
    options = {:iterations=>10000}
    paserk = 'k3.local-pw.a5cPboLhKgtNb_5C5FXniQuWVgChPXIwM4UKSEAjW3kAACcQzSQgm0Wh87-zAggZvwElhVYI__F7e0nCGL_tVsArrRMpKlkMfZrdi5d7ilpbqogeuiiKcHE9qBu2jTPYywyauZ4VymULdHlGn8fLCBZUGyNzXMbvb0qZS9kecwa4kQzP'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    key = pbkw.decode(paserk)
    expect(key.to_bytes.unpack1('H*')).to eq(unwrapped)
    expect(pbkw.decode(pbkw.encode(key, options)).to_bytes.unpack1('H*')).to eq(unwrapped)
  end

  it 'k3.local-pw-fail-1' do
    # skip('slow tests run only on command in CI') if ENV['CI'] && !ENV['SLOW_CI']
    password = '636f727265637420686f727365206261747465727920737461706c66'
    options = {:iterations=>10000}
    paserk = 'k3.local-pw.meWTPJohkeLsaKvlgigDksM935uSCUO3jvjEEHAK28QAAAPoNoLFUMJwo8QHOp5bJpbNzk-ZD_Q6jPtk0XhX4ctVhZnJ3ydru5AuXObwRudmG_RNK3PsJ7kpLSw15Vncc5vmGIkae4DKmBmPI1h3PmOxMGX_hj9DNfu1MIEEm9ukhKQq'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    expect do
      pbkw.decode(paserk)
    end.to raise_error(Paseto::InvalidAuthenticator)
  end

  it 'k3.local-pw-fail-2' do
    # skip('slow tests run only on command in CI') if ENV['CI'] && !ENV['SLOW_CI']
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:iterations=>10000}
    paserk = 'k3.local-pw.meWTPJohkeLsaKvlgigDksM935uSCUO3jvjEEHAK28QAAAPoNoLFUMJwo8QHOp5bJpbNzk-ZD_Q6jPtk0XhX4ctVhZnJ3ydru5AuXObwRudmG_RNK3PsJ7kpLSw15Vncc5vmGIkae4DKmBmPI1h3PmOxMGX_hj9DNfu1MIEEm1vkhLQr'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version3.new, password)

    expect do
      pbkw.decode(paserk)
    end.to raise_error(Paseto::InvalidAuthenticator)
  end

  it 'k3.local-pw-fail-3' do
    # skip('slow tests run only on command in CI') if ENV['CI'] && !ENV['SLOW_CI']
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>67108864, :opslimit=>2}
    paserk = 'k4.local-pw.cyacmXuslYEP8Xyheh9i-AAAAAAQAAAAAAAAAwAAAAEJh5jS-CAQP9grqo6xhuNMwmjcs6yTAvBjOW2HwZyBrBd0NNs6btknqo-6e-tyXJebU5S5918-es1Y9jhF1dOjMW0gDrsWkPoWT3Vy_poNxjIQHxHOHXaa'
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
