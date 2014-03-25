require 'spec_helper'

describe OmniAuth::Strategies::Imis do
  before(:each) { @strategy = OmniAuth::Strategies::Imis.new(:provider)}

  it { expect(@strategy).to be_kind_of OmniAuth::Strategies::OAuth2 }

  context 'client options' do
    it 'should have correct name' do
      expect(@strategy.options.name).to eq('imis')
    end

    it 'should have correct user_info_url' do
      expect(@strategy.options.client_options.user_info_url).to eq('/ssobsb_Webservices/wsblueskybroadcast.asmx/BlueSkyBroadcastGetUserProfile')
    end

    it 'should have correct authorize_url' do
      expect(@strategy.options.client_options.authorize_url).to eq('/ssobsb/sso.aspx')
    end
  end

  context '#user_info_url' do
    it 'returns url for getting information' do
      url = 'http://store.atsol.org/ssobsb_Webservices/wsblueskybroadcast.asmx/BlueSkyBroadcastGetUserProfile'

      expect(@strategy.send('user_info_url')).to be_eql url
    end
  end

  context '#authorize_url' do
    it 'returns url for authorization' do
      url = 'http://store.atsol.org/ssobsb/sso.aspx'

      expect(@strategy.send('authorize_url')).to be_eql url
    end
  end

  context '#get_user_info' do
    it 'returns correct hash' do
      stub_request(:any, @strategy.send('user_info_url') + "?token=123456").
        to_return(:body => IO.read("spec/fixtures/response.xml"), :status => 200, headers: {'content-type' => 'application/xml'})

      @strategy.stub(:access_token) { {token: '123456'} }
      returned = { id: '111', first_name: 'test', last_name: 'user', email: 'test@user.com' }

      expect(@strategy.get_user_info).to be_eql returned
    end
  end
end