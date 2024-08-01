require 'spec_helper'
require 'metasploit/framework/login_scanner/jenkins'

RSpec.describe Metasploit::Framework::LoginScanner::Jenkins do
  subject(:http_scanner) { described_class.new('host' => 'nosuchplace.metasploit.com') }

  let(:successful_auth_response) do
    res = Rex::Proto::Http::Response.new(302, 'Found')
    res.headers['Location'] = '/'
    res.headers['Set-Cookie'] = 'CGISESSID=NEWSESSIONID;'
    res
  end

  let(:fail_auth_response) do
    Rex::Proto::Http::Response.new(200, 'OK')
  end

  before do
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(successful_auth_response)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
  end

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base', has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  context '#set_sane_defaults' do
    context 'without ssl, without port' do
      it "should default :port to #{described_class::DEFAULT_PORT}" do
        expect(http_scanner.ssl).to be_falsey
        expect(http_scanner.port).to eq(described_class::DEFAULT_PORT)
      end
    end

    context 'with ssl, without port' do
      subject(:http_scanner) { described_class.new(ssl: true) }

      it "should set :port to default ssl port (#{described_class::DEFAULT_SSL_PORT})" do
        expect(http_scanner.ssl).to be_truthy
        expect(http_scanner.port).to eq(described_class::DEFAULT_SSL_PORT)
      end
    end

    context 'without ssl, with default port' do
      subject(:http_scanner) { described_class.new(port: described_class::DEFAULT_PORT) }

      it 'should set ssl to false' do
        expect(http_scanner.port).to eq(described_class::DEFAULT_PORT)
        expect(http_scanner.ssl).to be_falsey
      end
    end

    context 'without ssl, with default SSL port' do
      subject(:http_scanner) { described_class.new(port: described_class::DEFAULT_SSL_PORT) }

      it 'should set ssl to true' do
        expect(http_scanner.ssl).to be_truthy
        expect(http_scanner.port).to eq(described_class::DEFAULT_SSL_PORT)
      end
    end

    context 'without ssl, with non-default port' do
      subject(:http_scanner) { described_class.new(port: 0) }

      it 'should not set ssl' do
        expect(http_scanner.ssl).to be_falsey
        expect(http_scanner.port).to eq(0)
      end
    end

  end

  context '#attempt_login' do
    let(:pub_blank) {
      Metasploit::Framework::Credential.new(
        paired: 'true',
        public: 'public',
        private: ''
      )
    }

    it 'Rex::ConnectionError should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Rex::ConnectionError)

      expect { http_scanner.attempt_login(pub_blank).status }.to raise_error(Rex::ConnectionError)
    end

    context 'when a timeout occurs' do
      it 'Timeout::Error should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
        allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(Timeout::Error)

        expect { http_scanner.attempt_login(pub_blank).status }.to raise_error Rex::ConnectionError
      end
    end

    it 'EOFError should result in status Metasploit::Model::Login::Status::UNABLE_TO_CONNECT' do
      allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect).and_raise(EOFError)

      expect { http_scanner.attempt_login(pub_blank).status }.to raise_error Rex::ConnectionError
    end
  end
end
