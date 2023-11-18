# frozen_string_literal: true

RSpec.describe "PASERK k4.local-pw Test Vectors" do
  it 'k4.local-pw-1', :sodium, :slow do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>67108864, :opslimit=>2}
    paserk = 'k4.local-pw.9VvzoqE_i23NOqsP9xoijQAAAAAEAAAAAAAAAgAAAAG_uxDZC-NsYyOW8OUOqISJqgHN8xIfAXiPfmFTfB4GPidUzm4aKzMGJmZtRPeyZCV11MxEJS3VMIRHXxYsfUQsmWLALpFwqUhxZdk_ymFcK2Nk0-N7CVp-'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = Paseto::Paserk.pbkw(key: key, password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k4.local-pw-2', :sodium, :slow do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.local-pw.cyacmXuslYEP8Xyheh9i-AAAAAAQAAAAAAAAAwAAAAEJh5jS-CAQP9grqo6xhuNMwmjcs6yTAvBjOW2HwZyBrBd0NNs6btknqo-6e-tyXJebU5S5918-es1Y9jhF1dOjMW0gDrsWkPoWT3Vy_poNxjIQHxHOHXaa'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = Paseto::Paserk.pbkw(key: key, password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k4.local-pw-3', :sodium, :slow do
    unwrapped = '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
    password = 'correct horse battery staple'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.local-pw.1zXpYe7LSsL95YKf92kkJAAAAAAQAAAAAAAAAwAAAAG9WUsB_V2gVnTE1cCAs7RrS9-j22y2rcNixSycUw4_cryOPztPM8vASZw_BYHlQHxXqCl7wBS9NkUnMLa6b8e3ZNeaGiqaGFxRpmOK1Hal4GpHys6lC2Jw'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    key = Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    repacked = Paseto::Paserk.pbkw(key: key, password: password, options: options)
    unpacked = Paseto::Paserk.from_paserk(paserk: paserk, password: password)

    expect(unpacked).to eq(key)
  end

  it 'k4.local-pw-fail-1', :sodium, :slow do
    password = '636f727265637420686f727365206261747465727920737461706c66'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.local-pw.cyacmXuslYEP8Xyheh9i-AAAAAAQAAAAAAAAAwAAAAEJh5jS-CAQP9grqo6xhuNMwmjcs6yTAvBjOW2HwZyBrBd0NNs6btknqo-6e-tyXJebU5S5918-es1Y9jhF1dOjMW0gDrsWkPoWT3Vy_poNxjIQHxHOHXaa'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    expect do
      Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    end.to raise_error(Paseto::InvalidAuthenticator)

    expect do
      pbkw.encode(Paseto::V3::Local.new(ikm: 0.chr * 32), options)
    end.to raise_error(Paseto::LucidityError)
  end

  it 'k4.local-pw-fail-2', :sodium, :slow do
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:memlimit=>268435456, :opslimit=>3}
    paserk = 'k4.local-pw.cyacmXuslYEP8Xyheh9i-AAAAAAQAAAAAAAAAwAAAAEJh5jS-CAQP9grqo6xhuNMwmjcs6yTAvBjOW2HwZyBrBd0NNs6btknqo-6e-tyXJebU5S5918-es1Y9jhF1dOjMW0gDrsWkPoWT3Vy_poNxjIQHyHOHXbb'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    expect do
      Paseto::Paserk.from_paserk(paserk: paserk, password: password)
    end.to raise_error(Paseto::InvalidAuthenticator)

    expect do
      pbkw.encode(Paseto::V3::Local.new(ikm: 0.chr * 32), options)
    end.to raise_error(Paseto::LucidityError)
  end

  it 'k4.local-pw-fail-3', :sodium, :slow do
    password = '636f727265637420686f727365206261747465727920737461706c65'
    options = {:iterations=>10000}
    paserk = 'k3.local-pw.BZtl8KfhFR8CCZp6hB0V2yMWttTMpK_U8HiKxnuvMI0AACcQIm4KcJGvG1kfptqCbQxzQUOp72AzgtmhCLVP1mn3orDRJIpoDzRj82dc1cMnANbUsEdcYVG8xzSuCt99zfCjQnQ2rIKbKRM66gafzcSWmD9iMoY3W6KUaN56t0P-ODV2'
    pbkw = Paseto::Operations::PBKW.new(Paseto::Protocol::Version4.instance, password)

    expect do
      pbkw.decode(paserk)
    end.to raise_error(Paseto::LucidityError)

    expect do
      pbkw.encode(Paseto::V3::Local.new(ikm: 0.chr * 32), options)
    end.to raise_error(Paseto::LucidityError)
  end
end
