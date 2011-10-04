require 'teststrap'
require 'sinatra/cas_client'
require 'examples/sinatra/server'

context Sinatra::CasClient do
  app(Server)
  
  # context "A protected resource" do
    # setup { get '/' }  
    # asserts(:status).equals(401)
    # asserts(:body).equals("Unauthorised!")
  # end
  # 
  # context "new service ticket successfully" do    
    # setup {
      # pgt = CASClient::ProxyGrantingTicket.new(
        # "PGT-1308586001r9573FAD5A8C62E134A4AA93273F226BD3F0C3A983DCCCD176",
        # "PGTIOU-1308586001r29DC1F852C95930FE6694C1EFC64232A3359798893BC0B")
      # 
      # raw_text = "<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">
      # <cas:authenticationSuccess>
      # <cas:user>rich.yarger@vibes.com</cas:user>
      # <cas:proxyGrantingTicket>PGTIOU-1308586001r29DC1F852C95930FE6694C1EFC64232A3359798893BC0B</cas:proxyGrantingTicket>
      # </cas:authenticationSuccess>
      # </cas:serviceResponse>"
      # response = CASClient::ValidationResponse.new(raw_text)
      # any_instance_of(CASClient::Client, :request_cas_response => response)
      # any_instance_of(CASClient::Client, :retrieve_proxy_granting_ticket => pgt)
      # post "/", { :ticket => "someticket" } 
    # }
    # asserts(:status).equals(200)      
    # 
  # end
  
  context "new service ticket with invalid service ticket" do    
    setup {
      raw_text = "<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">
                    <cas:authenticationFailure>Some Error Text</cas:authenticationFailure>
                  </cas:serviceResponse>"
      response = CASClient::ValidationResponse.new(raw_text)      
      any_instance_of(CASClient::Client, :request_cas_response => response)
      
      post "/", { :ticket => "someticket" } 
    }
    asserts(:status).equals(401)     
    
  end
end
