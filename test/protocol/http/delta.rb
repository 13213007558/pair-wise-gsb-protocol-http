# frozen_string_literal: true

require "protocol/http/delta"
require "protocol/http/request"
require "protocol/http/response"

describe Protocol::HTTP::Delta do
	let(:delta) {Protocol::HTTP::Delta}
	
	let(:base) {"<html><body>Hello World!</body></html>"}
	let(:base_etag) {"\"abc123\""}
	
	let(:instance) {"<html><body>Hello Brave New World!</body></html>"}
	let(:response) do
		Protocol::HTTP::Response[200, {"content-type" => "text/html", "etag" => "\"def456\""}, [instance]]
	end
	
	describe ".accepts?" do
		it "accepts requests with vcdiff in the a-im header" do
			request = Protocol::HTTP::Request.new(nil, nil, "GET", "/", nil, Protocol::HTTP::Headers["a-im" => "vcdiff"], nil)
			
			expect(delta.accepts?(request)).to be == true
		end
		
		it "accepts requests with multiple instance manipulations" do
			request = Protocol::HTTP::Request.new(nil, nil, "GET", "/", nil, Protocol::HTTP::Headers["a-im" => "gzip, vcdiff"], nil)
			
			expect(delta.accepts?(request)).to be == true
		end
		
		it "does not accept requests without vcdiff" do
			request = Protocol::HTTP::Request.new(nil, nil, "GET", "/", nil, Protocol::HTTP::Headers["a-im" => "gzip"], nil)
			
			expect(delta.accepts?(request)).to be == false
		end
		
		it "does not accept requests without an a-im header" do
			request = Protocol::HTTP::Request.new(nil, nil, "GET", "/", nil, Protocol::HTTP::Headers.new, nil)
			
			expect(delta.accepts?(request)).to be == false
		end
	end
	
	describe ".encode_response" do
		it "produces a 226 response with instance manipulation headers" do
			delta_response = delta.encode_response(response, base, base_etag)
			
			expect(delta_response.status).to be == 226
			expect(delta_response.headers["im"]).to be(:include?, "vcdiff")
			expect(delta_response.headers["delta-base"]).to be == base_etag
			expect(delta_response.headers["content-type"]).to be == "text/html"
			expect(delta_response.headers["etag"]).to be == "\"def456\""
			expect(delta_response.headers["vary"]).to be(:include?, "a-im")
			expect(delta_response.headers["vary"]).to be(:include?, "if-none-match")
			expect(delta_response.headers).not.to be(:include?, "content-length")
			
			# The delta is smaller than the full instance:
			expect(delta_response.body.join.bytesize).to be < instance.bytesize
		end
		
		it "rejects non-200 responses" do
			response = Protocol::HTTP::Response[404, {}, ["not found"]]
			
			expect do
				delta.encode_response(response, base, base_etag)
			end.to raise_exception(ArgumentError, message: be =~ /status/)
		end
	end
	
	describe ".decode_response" do
		it "reconstructs the full response" do
			delta_response = delta.encode_response(response, base, base_etag)
			
			reconstructed = delta.decode_response(delta_response, base, base_etag)
			
			expect(reconstructed.status).to be == 200
			expect(reconstructed.read).to be == instance
			expect(reconstructed.headers["content-type"]).to be == "text/html"
			expect(reconstructed.headers["etag"]).to be == "\"def456\""
			expect(reconstructed.headers).not.to be(:include?, "im")
			expect(reconstructed.headers).not.to be(:include?, "delta-base")
			expect(reconstructed.headers).not.to be(:include?, "content-length")
		end
		
		it "rejects responses with a different status" do
			expect do
				delta.decode_response(response, base, base_etag)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /expected status 226/)
		end
		
		it "rejects responses without an im header" do
			delta_response = delta.encode_response(response, base, base_etag)
			delta_response.headers.delete("im")
			
			expect do
				delta.decode_response(delta_response, base, base_etag)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /im/)
		end
		
		it "rejects responses with unsupported instance manipulations" do
			delta_response = delta.encode_response(response, base, base_etag)
			delta_response.headers["im"] = "gzip"
			
			expect do
				delta.decode_response(delta_response, base, base_etag)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /vcdiff/)
		end
		
		it "rejects responses without a delta-base header" do
			delta_response = delta.encode_response(response, base, base_etag)
			delta_response.headers.delete("delta-base")
			
			expect do
				delta.decode_response(delta_response, base, base_etag)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /delta-base/)
		end
		
		it "rejects a mismatched base entity tag" do
			delta_response = delta.encode_response(response, base, base_etag)
			
			expect do
				delta.decode_response(delta_response, base, "\"other\"")
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /does not match/)
		end
		
		it "never produces a 200 response from a mismatched base" do
			# The entity tag matches, but the base content is different:
			expect do
				delta_response = delta.encode_response(response, base, base_etag)
				delta.decode_response(delta_response, "completely different base content", base_etag)
			end.to raise_exception(Protocol::HTTP::Delta::Error)
			
			expect do
				delta_response = delta.encode_response(response, base, base_etag)
				delta.decode_response(delta_response, "", base_etag)
			end.to raise_exception(Protocol::HTTP::Delta::Error)
		end
	end
end
