require 'sinatra/base'
require 'sinatra/cas_client'
require 'sinatra/cas_client_helper'

class Server < Sinatra::Base
  register Sinatra::CasClient
  helpers Sinatra::CasClientHelper

  use Rack::Logger

  configure do
    set :config, { :cas_base_url => "https://localhost/", :logger => $LOGGER   }
    set :client, CASClient::Client.new(settings.config)
    set :log, settings.client.log
  end
  
  protect_with_cas '/'  
  get '/' do
    'Hello world!'
  end
  
#  post '/' do
#    
#  end
  
  error 500 do
    File.open("500.html", "w+") { |f| f.write(response.body) }
  end
  
end
